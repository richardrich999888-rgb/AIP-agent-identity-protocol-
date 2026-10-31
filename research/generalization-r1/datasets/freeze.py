"""Single-author synthetic evaluation; no learned or independently authored semantics."""
import hashlib,json,pathlib,random
ROOT=pathlib.Path(__file__).parent

def generate(seed,n):
 r=random.Random(seed); rows=[]
 for i in range(n):
  kind=['exact','agree','disagree','missing','cross_tenant','hypothetical','large'][i%7]
  stock=r.randint(10,100); need=r.randint(1,120); cap=r.randint(10,100)
  alternatives=sorted(set([stock] if kind=='exact' else [max(0,stock-10),stock+10]))
  if kind=='agree': alternatives=[need+1,need+20]; cap=need+30
  if kind=='disagree': alternatives=[max(0,need-1),need+1];cap=need+30
  if kind=='large': alternatives=list(range(1,2001));cap=need+30
  bins=[cap,cap+10]; weights=[1,2]; limit=r.randint(100,300)
  expected='ABSTAIN'
  # Independent gold oracle: possible available allocations are bounded; approval
  # iff every possible stock/bin/weight world meets demand and weight constraint.
  lo=min(min(alternatives),min(bins))>=need and need*max(weights)<=limit
  hi=min(max(alternatives),max(bins))>=need and need*min(weights)<=limit
  if kind not in ['missing','cross_tenant','hypothetical']:
   expected='SHIP' if lo else ('HOLD' if not hi else 'ABSTAIN')
  rows.append(dict(id=f'{seed}-{i}',kind=kind,request=f'For order Q{i}, assess dispatch of {need} cartons; alternate stock counts must remain unresolved.',tenant='alpha',record_tenant='beta' if kind=='cross_tenant' else 'alpha',intent='simulate' if kind=='hypothetical' else 'assess',stock=[] if kind=='missing' else alternatives,capacity=bins,unit_weight=weights,limit=limit,need=need,expected=expected))
 return rows
if __name__=='__main__':
 hashes={}
 for name,seed,n in [('dev',712,42),('heldout',941,280)]:
  p=ROOT/(name+'.json');p.write_text(json.dumps(generate(seed,n),sort_keys=True,indent=1)+'\n');hashes[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
 (ROOT/'manifest.json').write_text(json.dumps({'sha256':hashes,'author':'single assistant; synthetic, not independent authorship','policy':'Exact SHIP/HOLD/ABSTAIN. Abstention correct only when gold ABSTAIN. Quality denominator all cases. No model or acquisition claim. Frozen before methods.'},indent=2)+'\n')
