import {runResearchReplay} from "./runtime.mjs";
self.addEventListener("message",async({data})=>{
  try {
    const result=await runResearchReplay(data.sample,data.check,async name=>{
      const response=await fetch(new URL(name,self.location.href),{credentials:"same-origin",redirect:"error"});
      if(!response.ok)throw Error("The signed replay assets are unavailable.");
      return response.arrayBuffer();
    });
    self.postMessage({ok:true,result});
  }catch(error){self.postMessage({ok:false,message:error.message});}
});
