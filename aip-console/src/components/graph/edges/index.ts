import type { EdgeTypes } from "@xyflow/react";
import {
  AccountabilityEdge,
  VerifiedEdge,
  BrokenEdge,
  TamperedEdge,
} from "./AccountabilityEdge";
import { EdgeMarkerDefs } from "./EdgeMarkerDefs";

export {
  AccountabilityEdge,
  VerifiedEdge,
  BrokenEdge,
  TamperedEdge,
  EdgeMarkerDefs,
};

export const accountabilityEdgeTypes: EdgeTypes = {
  accountability: AccountabilityEdge,
  verified: VerifiedEdge,
  broken: BrokenEdge,
  tampered: TamperedEdge,
};

export const edgeTypes = accountabilityEdgeTypes;
