// Persistent JSON stores with fsync-on-write (survive restarts).
// Two files in STATE_DIR:
//   seen-proofs.json  — { proof_tx (lowercased) : { task_id, at } }
//   idempotency.json  — { task_id : stored response body object }
import fs from "node:fs";
import path from "node:path";

function atomicWriteJson(filePath, obj) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${filePath}.tmp-${process.pid}`;
  const fd = fs.openSync(tmp, "w");
  try {
    fs.writeFileSync(fd, JSON.stringify(obj, null, 2));
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, filePath);
  // fsync the directory so the rename itself is durable
  try {
    const dfd = fs.openSync(dir, "r");
    try {
      fs.fsyncSync(dfd);
    } finally {
      fs.closeSync(dfd);
    }
  } catch {
    /* directory fsync is best-effort on some filesystems */
  }
}

export class JsonStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.data = {};
    try {
      this.data = JSON.parse(fs.readFileSync(filePath, "utf8"));
      if (!this.data || typeof this.data !== "object") this.data = {};
    } catch {
      this.data = {};
    }
  }
  get(key) {
    return this.data[key];
  }
  has(key) {
    return Object.prototype.hasOwnProperty.call(this.data, key);
  }
  set(key, value) {
    this.data[key] = value;
    atomicWriteJson(this.filePath, this.data);
  }
  delete(key) {
    delete this.data[key];
    atomicWriteJson(this.filePath, this.data);
  }
  size() {
    return Object.keys(this.data).length;
  }
}
