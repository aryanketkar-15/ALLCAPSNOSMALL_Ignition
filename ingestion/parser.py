import pandas as pd
from datetime import datetime, timezone

from .schema import AlertSchema

class LogParser:
    def parse(self, raw_row: dict, dataset: str) -> dict:
        fields = {}
        fields['raw_log'] = str(raw_row)
        
        if dataset == 'beth':
            fields['event_type'] = str(raw_row.get('eventId'))
            
            userId = raw_row.get('userId')
            if userId is not None and not pd.isna(userId):
                fields['source_ip'] = str(userId)
            else:
                fields['source_ip'] = None
            
            sus = raw_row.get('sus')
            try:
                fields['severity_raw'] = float(sus) if (sus is not None and not pd.isna(sus)) else 0.0
            except (TypeError, ValueError):
                fields['severity_raw'] = 0.0
            
            evil = raw_row.get('evil')
            if evil is not None and not pd.isna(evil):
                fields['label'] = int(evil)
                
            timestamp = raw_row.get('timestamp')
            if timestamp is not None and not pd.isna(timestamp):
                fields['timestamp'] = datetime.utcfromtimestamp(float(timestamp)).replace(tzinfo=timezone.utc)
            else:
                fields['timestamp'] = datetime.now(timezone.utc)
                
        elif dataset == 'unsw':
            srcip = raw_row.get('srcip')
            fields['source_ip'] = srcip if not pd.isna(srcip) else None
            
            dstip = raw_row.get('dstip')
            fields['dest_ip'] = dstip if not pd.isna(dstip) else None
            
            dsport = raw_row.get('dsport')
            if dsport is not None and not pd.isna(dsport) and str(dsport).strip() != '-':
                try:
                    fields['port'] = int(dsport)
                except ValueError:
                    fields['port'] = None
                    
            proto = raw_row.get('proto')
            fields['protocol'] = proto if not pd.isna(proto) else None
            
            attack_cat = raw_row.get('attack_cat')
            fields['event_type'] = attack_cat if (attack_cat is not None and not pd.isna(attack_cat) and str(attack_cat).strip() != '') else 'normal'
            
            label = raw_row.get('Label')
            if label is not None and not pd.isna(label):
                fields['label'] = int(label)
                
            fields['timestamp'] = datetime.now(timezone.utc)
            
        return AlertSchema(**fields).dict()

    def batch_parse(self, filepath: str, dataset: str) -> pd.DataFrame:
        try:
            chunks = pd.read_csv(filepath, chunksize=10000)
        except UnicodeDecodeError:
            chunks = pd.read_csv(filepath, chunksize=10000, encoding='latin-1')
            
        results = []
        for chunk in chunks:
            chunk = chunk.rename(columns=str.strip)
            parsed_series = chunk.apply(lambda row: self.parse(row.to_dict(), dataset), axis=1)
            results.append(pd.DataFrame(parsed_series.tolist()))
            
        if results:
            return pd.concat(results).reset_index(drop=True)
        return pd.DataFrame()
