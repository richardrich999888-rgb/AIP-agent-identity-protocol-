import { verifyObserver,evaluateAuthority } from "./observer.mjs";
import {parseArgs} from "node:util";
const [mode,...args]=process.argv.slice(2);
const options=Object.fromEntries(["binary","batches","health","observer","key","key-version","bundle","trust"].map(name=>[name,{type:"string"}]));
try {
  const {values}=parseArgs({args,options,strict:true,allowPositionals:false});
  let result;
  if(mode==="observe")result=await verifyObserver({binary:values.binary,batches:values.batches,health:values.health,observerId:values.observer,publicKey:values.key,keyVersion:Number(values["key-version"]),provenance:"Operator-supplied archive"});
  else if(mode==="evaluate")result=await evaluateAuthority({binary:values.binary,bundle:values.bundle,trust:values.trust,provenance:"Operator-supplied archive"});
  else throw Error("Choose observe or evaluate.");
  console.log(JSON.stringify(result,null,2));if(!result.accepted)process.exitCode=1;
} catch(error){console.error(error.message);process.exitCode=2;}
