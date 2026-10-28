"use strict";
(() => {
  let credential = "";
  let generation = 0;
  const byId = id => document.getElementById(id);
  const display = (id, value) => {byId(id).textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);};
  async function read(path) {
    if (!credential) throw new Error("Connect with a Reader credential first");
    const current = generation;
    const response = await fetch(path, {headers: {Authorization: "Bearer " + credential, Accept: "application/json"},
      redirect: "error", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(10000)});
    if (!response.ok) throw new Error("Request refused or unavailable (HTTP " + response.status + ")");
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      for (;;) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 262144) throw new Error("Response exceeds console limit");
        chunks.push(value);
      }
    } finally {await reader.cancel(); reader.releaseLock();}
    if (current !== generation) throw new Error("Session changed; result discarded");
    const bytes = new Uint8Array(size);
    let offset = 0;
    chunks.forEach(chunk => {bytes.set(chunk, offset); offset += chunk.length;});
    return JSON.parse(new TextDecoder().decode(bytes));
  }
  function disconnect() {
    credential = ""; generation++;
    byId("credential").value = "";
    byId("refresh").disabled = true;
    byId("agents").replaceChildren();
    for (const id of ["health", "coverage", "activity", "evidence", "verdict", "deployments", "deployment"]) display(id, "Disconnected");
    display("status", "Disconnected");
  }
  async function refresh() {
    const requestGeneration = generation;
    read("/v1/deployments?limit=25&offset=0")
      .then(value => {if (generation === requestGeneration) display("deployments", value);})
      .catch(error => {if (generation === requestGeneration) display("deployments", error.message);});
    const [health, coverage, page] = await Promise.all([read("/v1/health"), read("/v1/coverage"), read("/v1/agents?limit=25&offset=0")]);
    display("health", health); display("coverage", coverage);
    const items = page.items.map(agent => {
      const li = document.createElement("li"), button = document.createElement("button");
      button.textContent = agent.agent_id + " · " + agent.evidence_count + " signed packet(s)";
      button.addEventListener("click", () => read("/v1/agents/" + encodeURIComponent(agent.agent_id) + "/activity?limit=25&offset=0")
        .then(value => display("activity", value)).catch(error => display("status", error.message)));
      li.append(button); return li;
    });
    if (!items.length) {const li = document.createElement("li"); li.textContent = "No packet identities in this tenant."; items.push(li);}
    byId("agents").replaceChildren(...items);
    display("status", "Connected · first 25 stored identities · refreshed " + new Date().toISOString());
  }
  byId("connect").addEventListener("submit", async event => {
    event.preventDefault(); generation++;
    credential = byId("credential").value; byId("credential").value = "";
    try {
      const access = await read("/v1/access");
      if (access.role !== "reader") throw new Error("This console requires a Reader credential");
      byId("refresh").disabled = false; await refresh();
    } catch (error) {disconnect(); display("status", error.message);}
  });
  byId("refresh").addEventListener("click", () => refresh().catch(error => display("status", error.message)));
  byId("disconnect").addEventListener("click", disconnect);
  byId("deployment-form").addEventListener("submit", async event => {
    event.preventDefault(); const current = generation;
    try {
      const value = await read("/v1/deployments/" + encodeURIComponent(byId("deployment-name").value));
      if (current === generation) display("deployment", value);
    } catch (error) {if (current === generation) display("deployment", error.message);}
  });
  byId("evidence-form").addEventListener("submit", async event => {
    event.preventDefault();
    try {
      const id = encodeURIComponent(byId("evidence-id").value);
      const domain = byId("evidence-kind").value === "observations" ? "observations" : "evidence";
      const [metadata, verification] = await Promise.all([read("/v1/" + domain + "/" + id + "/metadata"), read("/v1/" + domain + "/" + id + "/verification")]);
      display("evidence", {metadata, verification});
    } catch (error) {display("evidence", error.message);}
  });
  byId("verdict-form").addEventListener("submit", event => {
    event.preventDefault(); read("/v1/verdicts/" + encodeURIComponent(byId("verdict-id").value))
      .then(value => display("verdict", value)).catch(error => display("verdict", error.message));
  });
  setInterval(() => {if (credential && !document.hidden) refresh().catch(error => display("status", error.message));}, 15000);
})();
