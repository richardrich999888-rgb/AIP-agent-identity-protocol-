from itertools import product
from warehouse_methods import interval,exhaustive
from benchmark import wilson

def test_interval_against_enumeration_exhaustive_small_space():
 for a,b,c,d,n,limit in product(range(1,5),repeat=6):
  x=dict(tenant='a',record_tenant='a',intent='assess',stock=[a,b],capacity=[c,d],unit_weight=[1,2],need=n,limit=limit)
  assert interval(x)==exhaustive(x)
def test_bounds_and_empty():
 assert wilson(0,0) is None
 for n in (1,2,100):
  for k in range(n+1):
   lo,hi=wilson(k,n); assert 0<=lo<=hi<=1 and lo-1e-15<=k/n<=hi+1e-15

def test_short_circuit_matches_oracle():
 from warehouse_methods import short_circuit
 for need in range(1,10):
  for limit in range(1,20):
   x=dict(tenant='a',record_tenant='a',intent='assess',stock=list(range(1,20)),capacity=[3,6],unit_weight=[1,2],need=need,limit=limit)
   assert short_circuit(x)==exhaustive(x)

def test_transport_normalization_does_not_extract_arbitrary_labels():
 from score_llm import normalize
 assert normalize('<think>\n\n</think>\nSHIP')=='SHIP'
 assert normalize('<think>HOLD</think>SHIP')!='SHIP'
 assert normalize('Maybe SHIP')!='SHIP'
