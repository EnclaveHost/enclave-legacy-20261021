// One listener belongs to exactly one app and circuit. Never dispatch to another
// deployment based on a hostname supplied by a public provider or visitor.
import net from 'node:net';
import {clientHelloName} from './client-hello.mjs';

export function validateAppNames(deploymentId,names) {
  if (!/^0x[0-9a-f]{64}$/.test(deploymentId || '') || !Array.isArray(names) || !names.length || names.length > 64 ||
    names.some(n => typeof n !== 'string' || n.length > 253 || !n.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))))
    throw new Error('app identity and hostnames required');
  return names;
}
// admitName (optional): name -> boolean, consulted only for a name outside `names`, at each ClientHello - the
// listener's own app's owner-committed names while they are proven (owner-names.mjs). It can only admit to THIS app.
export async function createAppIngress({deploymentId, host = '127.0.0.1', port = 0,
  names, authorize, forward, admitName = null, maxConnections = 1024, allowNoSni = false, onError = () => {}}) {
  validateAppNames(deploymentId,names);
  if(admitName!==null&&typeof admitName!=='function')throw new Error('admitName must be a function');
  const allowedNames = new Set(names.map(n => n.toLowerCase()));
  const sockets = new Set();
  const server = net.createServer(socket => {
    if (sockets.size >= maxConnections || !authorize(deploymentId)) return socket.destroy();
    sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.on('error', () => {});
    socket.setTimeout(10000, () => socket.destroy());
    let hello = Buffer.alloc(0);
    const read = chunk => {
      hello = Buffer.concat([hello, chunk]);
      if (hello.length > 65536) return socket.destroy();
      const name = clientHelloName(hello);
      if (name === null) return;
      socket.pause(); socket.removeListener('data', read);
      const named = name && (allowedNames.has(name.toLowerCase()) || (admitName !== null && admitName(name.toLowerCase()) === true));
      if (!(name ? named : name === '' && allowNoSni) || !authorize(deploymentId)) return socket.destroy();
      socket.setTimeout(0); socket.unshift(hello);
      Promise.resolve().then(() => forward(socket, deploymentId)).catch(e => {onError(e);socket.destroy();});
    };
    socket.on('data', read);
  });
  await new Promise((resolve, reject) => {server.once('error', reject); server.listen(port, host, resolve);});
  return {port: server.address().port,
    revoke() {for (const socket of sockets) socket.destroy();},
    close() {server.close(); for (const socket of sockets) socket.destroy();},
  };
}
