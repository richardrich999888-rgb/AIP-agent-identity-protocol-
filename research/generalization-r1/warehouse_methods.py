"""Established deterministic methods, not a new model architecture."""
from itertools import product

def authorized(x):
 return x['tenant']==x['record_tenant'] and x['intent']=='assess' and all(x[k] for k in ('stock','capacity','unit_weight'))
def decision(x,s,c,w):
 return 'SHIP' if s>=x['need'] and c>=x['need'] and x['need']*w<=x['limit'] else 'HOLD'
def eager(x):
 return decision(x,x['stock'][0],x['capacity'][0],x['unit_weight'][0]) if authorized(x) else 'ABSTAIN'
def conservative(x):
 return eager(x) if all(len(x[k])==1 for k in ('stock','capacity','unit_weight')) else 'ABSTAIN'
def exhaustive(x):
 if not authorized(x): return 'ABSTAIN'
 outcomes={decision(x,*v) for v in product(x['stock'],x['capacity'],x['unit_weight'])}
 return next(iter(outcomes)) if len(outcomes)==1 else 'ABSTAIN'
def interval(x):
 if not authorized(x): return 'ABSTAIN'
 worst=decision(x,min(x['stock']),min(x['capacity']),max(x['unit_weight']))
 best=decision(x,max(x['stock']),max(x['capacity']),min(x['unit_weight']))
 return worst if worst==best else 'ABSTAIN'
METHODS=dict(eager=eager,conservative=conservative,exhaustive=exhaustive,interval=interval)

def short_circuit(x):
 if not authorized(x): return 'ABSTAIN'
 first=None
 for v in product(x['stock'],x['capacity'],x['unit_weight']):
  got=decision(x,*v)
  if first is None:first=got
  elif first!=got:return 'ABSTAIN'
 return first
METHODS['short_circuit']=short_circuit
