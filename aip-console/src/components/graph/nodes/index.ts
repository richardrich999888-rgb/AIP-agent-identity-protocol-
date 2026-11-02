import type { NodeTypes } from "@xyflow/react";
import { PrincipalNode } from "./PrincipalNode";
import { AuthorityGrantNode } from "./AuthorityGrantNode";
import { DelegationNode } from "./DelegationNode";
import { AgentNode } from "./AgentNode";
import { DecisionNode } from "./DecisionNode";
import { ActionNode } from "./ActionNode";
import { ReceiptNode } from "./ReceiptNode";

export {
  PrincipalNode,
  AuthorityGrantNode,
  DelegationNode,
  AgentNode,
  DecisionNode,
  ActionNode,
  ReceiptNode,
};

export const accountabilityNodeTypes: NodeTypes = {
  principal: PrincipalNode,
  authority_grant: AuthorityGrantNode,
  delegation: DelegationNode,
  agent: AgentNode,
  decision: DecisionNode,
  action: ActionNode,
  receipt: ReceiptNode,
};

export const nodeTypes = accountabilityNodeTypes;
