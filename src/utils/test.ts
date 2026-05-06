
export const WTMP_TELEMETRY_SERVER = "https://wtmp-0xx-06ev8v2svds5d5bklshm8otgmk.aws-use2.surreal.cloud/";
  const url = `${WTMP_TELEMETRY_SERVER}sql`;

function escapeString(str: string): string {
  return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

const payload = {
  email: "foo.biz",
  os: "123",
  platform: "123",
  arch: "123",
  cpus: 123,
  memory: 123,
  ci_environment: "123",
  version: "123"
}

  const query = `CREATE telemetry SET email = '${escapeString(payload.email)}', os = '${escapeString(payload.os)}', platform = '${escapeString(payload.platform)}', arch = '${escapeString(payload.arch)}', cpus = ${payload.cpus}, memory = ${payload.memory}, ci_environment = ${payload.ci_environment ? `'${escapeString(payload.ci_environment)}'` : 'NONE'}, version = '${escapeString(payload.version)}'`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Accept': 'application/json',
      'surreal-ns': 'wtmp',
      'surreal-db': 'main'
    },
    body: query,
  })
  .then(response => response.text())
  .then(text => console.log("we got success", text))
  .catch(error => console.error("we got error", error));