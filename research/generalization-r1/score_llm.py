"""Post-run transport-format diagnostic. Original raw and strict scores retained."""
import json,pathlib,re,statistics,math,sys
from benchmark import wilson
R=pathlib.Path(__file__).parent

def normalize(text):
 return re.sub(r'^\s*<think>\s*</think>\s*','',text,count=1).strip()
def main():
 d=R/'results'/(sys.argv[1] if len(sys.argv)>1 else 'llm');raw=json.loads((d/'raw.json').read_text());output={}
 for mode in sorted({x['mode'] for x in raw}):
  p=[x for x in raw if x['mode']==mode];details=[]
  for x in p:
   s=normalize(x['response']['choices'][0]['message']['content']);got=s if s in ('SHIP','HOLD','ABSTAIN') else 'INVALID';details.append(dict(id=x['id'],expected=x['expected'],got=got))
  good=sum(x['got']==x['expected'] for x in details);ans=[x for x in details if x['got'] in ['SHIP','HOLD']];lat=sorted(x['wall_seconds'] for x in p)
  output[mode]=dict(n=len(p),strict_correct=sum(x['got']==x['expected'] for x in p),normalized_correct=good,accuracy_ci95=wilson(good,len(p)),released=len(ans),correct_released=sum(x['got']==x['expected'] for x in ans),incorrect_positive=sum(x['got']=='SHIP' and x['expected']!='SHIP' for x in details),invalid=sum(x['got']=='INVALID' for x in details),p50_wall_seconds=statistics.median(lat),p95_wall_seconds=lat[math.ceil(.95*len(lat))-1],prompt_tokens=sum(x['response'].get('usage',{}).get('prompt_tokens',0) for x in p),completion_tokens=sum(x['response'].get('usage',{}).get('completion_tokens',0) for x in p),predictions=details)
 (d/'normalized-summary.json').write_text(json.dumps(dict(policy='post-run diagnostic removes only EMPTY leading think wrapper; no label search, no gold-dependent corrections; strict results retained',modes=output),indent=1)+'\n')
 print(json.dumps({k:{a:b for a,b in v.items() if a!='predictions'} for k,v in output.items()},indent=2))
if __name__=='__main__':main()
