import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const EMPTY = () => ({ version: 2, watches: {}, alerts: [], audit: [] });

export class JsonStore {
  constructor(filePath) { this.filePath = filePath; this.data = EMPTY(); }
  async load() {
    try { this.data = { ...EMPTY(), ...JSON.parse(await readFile(this.filePath, 'utf8')) }; }
    catch (error) { if (error.code !== 'ENOENT') throw error; await this.save(); }
    return this.data;
  }
  async save() {
    await mkdir(dirname(this.filePath), { recursive: true });
    const temp = `${this.filePath}.tmp`;
    await writeFile(temp, `${JSON.stringify(this.data, null, 2)}\n`, 'utf8');
    await rename(temp, this.filePath);
  }
}
