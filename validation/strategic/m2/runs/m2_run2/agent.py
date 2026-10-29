import json,sys
print(json.dumps({"propose":{"tool_id":'loan-read',"arguments":{"loan_id": "L-1001"}}}),flush=True)
sys.stdin.readline()  # wait for the tool result relayed by the gateway
print(json.dumps({"propose_mismatch":{"tool_id":'loan-read',"arguments":{"loan_id":"L-9999"}}}),flush=True)
sys.stdin.readline()
