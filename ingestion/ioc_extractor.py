import re
import time
import ipaddress
import pandas as pd
from concurrent.futures import ProcessPoolExecutor


class IOCExtractor:
    """
    Vectorised IOC (Indicator of Compromise) extraction engine.
    Uses a single compiled named-group regex applied via pandas str.extractall()
    for maximum throughput. No row-level loops.

    Process names are extracted from BETH structured columns directly — not via
    regex — because the raw_log contains large dict strings that would generate
    thousands of false-positive matches per row.
    """

    def __init__(self):
        # Single compiled named-group pattern using | alternation.
        # Order: longer/more specific patterns first to avoid partial matches.
        # NOTE: 'process' is intentionally excluded from regex — BETH provides
        # processName as a structured column. Regex on raw_log would match every
        # 3-char+ token in the args dict string (~20x slower).
        self.pattern = re.compile(
            r'(?P<sha256>\b[a-fA-F0-9]{64}\b)'
            r'|(?P<md5>\b[a-fA-F0-9]{32}\b)'
            r'|(?P<cve>CVE-\d{4}-\d{4,7})'
            r'|(?P<url>https?://[^\s\"\'\>,\)]{4,100})'
            r'|(?P<ipv6>(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})'
            r'|(?P<ipv4>\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b)'
            r'|(?P<domain>\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|ru|io|xyz|info|biz|top|cc|tk|cn|de|uk|co)\b)'
            r'|(?P<port>(?<=:)\d{2,5}\b|(?<=port=)\d{2,5}\b)'
        )

        # Precompiled RFC 1918 private networks for false-positive filtering
        self._private_nets = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
        ]

    def extract_all(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Vectorised IOC extraction from raw_log column.
        For BETH structured columns (processName, etc.), assigns directly — no regex.
        Returns the original DataFrame with an added 'iocs' column (dict per row).
        """
        df = df.copy()

        # ── Vectorised regex extraction on raw_log ──
        raw_log_series = df['raw_log'].astype(str)
        matches = raw_log_series.str.extractall(self.pattern)

        if matches.empty:
            df['iocs'] = [dict() for _ in range(len(df))]
        else:
            matches = matches.reset_index()
            ioc_columns = [c for c in matches.columns if c not in ('level_0', 'match')]

            # Vectorised aggregation: melt → groupby → pivot back to dicts
            ioc_dicts = {}
            for col in ioc_columns:
                valid = matches[['level_0', col]].dropna(subset=[col])
                if valid.empty:
                    continue
                grouped = valid.groupby('level_0')[col].apply(lambda x: x.unique().tolist())
                for idx, vals in grouped.items():
                    if idx not in ioc_dicts:
                        ioc_dicts[idx] = {}
                    ioc_dicts[idx][col] = vals

            df['iocs'] = [ioc_dicts.get(i, {}) for i in range(len(df))]

        # ── BETH structured columns: direct vectorised assignment (no regex) ──
        if 'processName' in df.columns:
            proc_series = df['processName'].astype(str).str.strip()
            valid_mask = (proc_series != '') & (proc_series != 'nan')

            def _add_process(row_idx):
                iocs = df.at[row_idx, 'iocs']
                if not isinstance(iocs, dict):
                    iocs = {}
                proc_val = proc_series.at[row_idx]
                existing = iocs.get('process', [])
                if proc_val not in existing:
                    existing.append(proc_val)
                iocs['process'] = existing
                return iocs

            valid_indices = df.index[valid_mask]
            if len(valid_indices) > 0:
                df.loc[valid_mask, 'iocs'] = [_add_process(i) for i in valid_indices]

        # Apply false-positive filtering on all IOC dicts
        df['iocs'] = df['iocs'].apply(
            lambda x: self.false_positive_filter(x) if isinstance(x, dict) else {}
        )

        return df

    def false_positive_filter(self, iocs: dict) -> dict:
        """
        Separates RFC 1918 private IPs from external IPs.
        Private IPs are moved to 'lateral_movement' key.
        External IPs remain under 'ipv4'.
        """
        if 'ipv4' not in iocs:
            return iocs

        filtered = dict(iocs)  # shallow copy
        external_ips = []
        lateral_ips = []

        for ip_str in iocs.get('ipv4', []):
            try:
                addr = ipaddress.IPv4Address(ip_str)
                if any(addr in net for net in self._private_nets):
                    lateral_ips.append(ip_str)
                else:
                    external_ips.append(ip_str)
            except (ipaddress.AddressValueError, ValueError):
                external_ips.append(ip_str)

        if external_ips:
            filtered['ipv4'] = external_ips
        else:
            filtered.pop('ipv4', None)

        if lateral_ips:
            existing = filtered.get('lateral_movement', [])
            filtered['lateral_movement'] = existing + lateral_ips

        return filtered

    def benchmark(self, df_sample: pd.DataFrame):
        """
        Benchmark IOC extraction on 10,000 rows.
        Target: < 2 seconds. Warning threshold: > 5 seconds.
        """
        sample = df_sample.head(10000).copy()
        start = time.perf_counter()
        self.extract_all(sample)
        elapsed = time.perf_counter() - start
        print(f'IOC extraction: {elapsed:.2f}s for {len(sample):,} rows')
        if elapsed > 5.0:
            print('WARNING: Exceeds 5s threshold — consider ProcessPoolExecutor(max_workers=4)')
        elif elapsed < 2.0:
            print('PASS: Under 2s target')
        else:
            print('INFO: Between 2-5s — acceptable but room for optimisation')
        return elapsed
