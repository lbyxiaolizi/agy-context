// Format-aware, fixed-size patches. Reference signatures: justhil/agy-tool
// (https://github.com/justhil/agy-tool) and q1uuuu/agy-context (agy-patch.py);
// ARM64 patterns inspected on desktop 2.32.1 and agy CLI 1.4.12+.
// Never search/replace numeric limits globally: every code patch is scoped to
// its Go function and requires an exact, unique instruction sequence.
const PREFIX = 'google3/third_party/jetski/prompt/template_provider/templates/system_prompts/';
const CHECKPOINT = 'utils.GetCheckpointConfig';
const EXP_CHECKPOINT = 'config.applyFeatureProviderCheckpointOverrideConfig';
const SELECT_EXP_KEY = 'config.selectCheckpointExperimentKey';
const OFFERS_CW = 'model.SelectorModel.offersContextWindow';
const STORE_CW = 'store.(*Store).ContextWindow';
const STORE_CHOICE = 'store.(*Store).ContextWindowChoice';
const AUTO_COMPACT_OVERRIDE = 'store.AutoCompactOverride';
const APPLY_EDITS = 'genericsystemprompt.applyEdits';
const TARGET_SYMBOLS = new Set([
  CHECKPOINT,
  EXP_CHECKPOINT,
  SELECT_EXP_KEY,
  OFFERS_CW,
  STORE_CW,
  STORE_CHOICE,
  AUTO_COMPACT_OVERRIDE
]);
const CLI_SYMS = [OFFERS_CW, STORE_CW, STORE_CHOICE];

const MODES = ['stock', '512k', '900k', 'dynamic'];
const MODE_LIMITS = { '512k': 512000, '900k': 900000 };
const STOCK_LIMITS = new Set([256000, 200000, 128000]);

const NOP_ARM64 = 0xd503201f;
const RET_ARM64 = 0xd65f03c0;

const hex = value => Buffer.from(value.replaceAll(' ', ''), 'hex');
const words = (...values) => {
  const result = Buffer.alloc(values.length * 4);
  values.forEach((value, i) => result.writeUInt32LE(value >>> 0, i * 4));
  return result;
};

const RET_TRUE_ARM64 = words(0x52800020, 0xd65f03c0);
const RET_TRUE_X64 = hex('b801000000c3');

function bounds(buf, offset, size) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 || offset + size > buf.length) {
    throw new Error('二进制数据越界，拒绝修改');
  }
}
function u64(buf, offset) {
  bounds(buf, offset, 8);
  const value = Number(buf.readBigUInt64LE(offset));
  if (!Number.isSafeInteger(value)) throw new Error('不支持的二进制地址');
  return value;
}
function unique(buf, needle, start = 0, end = buf.length) {
  const found = buf.indexOf(needle, start);
  if (found < start || found + needle.length > end) return -1;
  const second = buf.indexOf(needle, found + 1);
  if (second >= 0 && second + needle.length <= end) throw new Error('发现重复补丁特征，拒绝修改');
  return found;
}

function layout(buf) {
  bounds(buf, 0, 64);
  const regions = [];
  let format, arch, text, pclntab;
  const add = (offset, size, address, executable, name = '') => {
    bounds(buf, offset, size);
    regions.push({ offset, size, address, executable, name });
    if (name === '__text' || name === '.text') text = address;
  };
  if (buf.readUInt32LE(0) === 0xfeedfacf) {
    format = 'Mach-O';
    const cpu = buf.readUInt32LE(4);
    arch = cpu === 0x100000c ? 'arm64' : cpu === 0x1000007 ? 'x64' : 'unknown';
    let off = 32;
    const count = buf.readUInt32LE(16);
    for (let i = 0; i < count; i++) {
      bounds(buf, off, 8);
      const cmd = buf.readUInt32LE(off), size = buf.readUInt32LE(off + 4);
      if (size < 8) throw new Error('无效 Mach-O load command');
      bounds(buf, off, size);
      if (cmd === 0x19) {
        bounds(buf, off, 72);
        const address = u64(buf, off + 24), fileoff = u64(buf, off + 40), filesize = u64(buf, off + 48);
        if (filesize) add(fileoff, filesize, address, !!(buf.readUInt32LE(off + 60) & 4));
        const sections = buf.readUInt32LE(off + 64);
        if (72 + sections * 80 > size) throw new Error('无效 Mach-O section table');
        for (let j = 0; j < sections; j++) {
          const s = off + 72 + j * 80;
          const name = buf.subarray(s, s + 16).toString().replace(/\0.*$/, '');
          if (name === '__text') text = u64(buf, s + 32);
          if (name === '__lrodata_gopcln' || name === '__gopclntab') pclntab = buf.readUInt32LE(s + 48);
        }
      }
      off += size;
    }
  } else if (buf.toString('ascii', 0, 2) === 'MZ') {
    format = 'PE';
    const pe = buf.readUInt32LE(0x3c);
    bounds(buf, pe, 112);
    if (buf.readUInt32LE(pe) !== 0x4550 || buf.readUInt16LE(pe + 24) !== 0x20b) throw new Error('仅支持 PE64');
    const machine = buf.readUInt16LE(pe + 4);
    arch = machine === 0x8664 ? 'x64' : machine === 0xaa64 ? 'arm64' : 'unknown';
    const imageBase = u64(buf, pe + 48);
    const count = buf.readUInt16LE(pe + 6), table = pe + 24 + buf.readUInt16LE(pe + 20);
    bounds(buf, table, count * 40);
    for (let i = 0; i < count; i++) {
      const s = table + i * 40;
      add(buf.readUInt32LE(s + 20), buf.readUInt32LE(s + 16), imageBase + buf.readUInt32LE(s + 12),
        !!(buf.readUInt32LE(s + 36) & 0x20000000), buf.toString('ascii', s, s + 8).replace(/\0.*$/, ''));
    }
  } else if (buf.readUInt32LE(0) === 0x464c457f && buf[4] === 2 && buf[5] === 1) {
    format = 'ELF';
    arch = buf.readUInt16LE(18) === 62 ? 'x64' : buf.readUInt16LE(18) === 183 ? 'arm64' : 'unknown';
    const table = u64(buf, 32), stride = buf.readUInt16LE(54), count = buf.readUInt16LE(56);
    if (stride < 56) throw new Error('无效 ELF program header');
    bounds(buf, table, stride * count);
    for (let i = 0; i < count; i++) {
      const s = table + i * stride;
      if (buf.readUInt32LE(s) === 1) add(u64(buf, s + 8), u64(buf, s + 32), u64(buf, s + 16), !!(buf.readUInt32LE(s + 4) & 1));
    }
  } else {
    throw new Error('不支持此可执行文件格式（需要 PE64、薄 Mach-O 64 或 ELF64 little-endian）');
  }
  const toOffset = (address, length = 1) => {
    const r = regions.find(r => address >= r.address && address + length <= r.address + r.size);
    if (!r) throw new Error('地址不在二进制文件映射范围内');
    return r.offset + address - r.address;
  };
  const toAddress = offset => {
    const r = regions.find(r => offset >= r.offset && offset < r.offset + r.size);
    if (!r) throw new Error('文件偏移不在映射范围内');
    return r.address + offset - r.offset;
  };
  return { format, arch, text, pclntab, regions, toOffset, toAddress };
}

function templateSlots(buf, image) {
  const anchor = Buffer.from(PREFIX + 'identity.tmpl');
  const nameOffset = unique(buf, anchor);
  if (nameOffset < 0) throw new Error('未找到内嵌 identity.tmpl 模板');
  const entry = Buffer.alloc(16);
  entry.writeBigUInt64LE(BigInt(image.toAddress(nameOffset)));
  entry.writeBigUInt64LE(BigInt(anchor.length), 8);
  const center = unique(buf, entry);
  if (center < 0) throw new Error('未找到 Go embed.FS 模板表');
  const slots = [];
  for (let k = -64; k <= 64; k++) {
    const pos = center + k * 48;
    if (pos < 0 || pos + 48 > buf.length) continue;
    let name, offset, capacity;
    try {
      const length = u64(buf, pos + 8);
      if (length < PREFIX.length || length > 300) continue;
      const start = image.toOffset(u64(buf, pos), length);
      name = buf.toString('utf8', start, start + length);
      if (!name.startsWith(PREFIX) || !name.endsWith('.tmpl')) continue;
      capacity = u64(buf, pos + 24);
      if (!capacity || capacity > 1024 * 1024) continue;
      offset = image.toOffset(u64(buf, pos + 16), capacity);
    } catch { continue; }
    name = name.slice(PREFIX.length);
    if (slots.some(s => s.name === name)) throw new Error('模板名称重复，拒绝修改');
    const raw = buf.toString('utf8', offset, offset + capacity);
    const content = raw.replace(/\{\{\/\* *\*\/\}\}$/, '').replace(/\{\{- \/\* *\*\/ -\}\}$/, '');
    slots.push({ name, offset, capacity, content, editable: name !== 'identity.tmpl' });
  }
  if (!slots.some(s => s.name === 'identity.tmpl')) throw new Error('模板表缺少身份模板');
  return slots.sort((a, b) => a.name.localeCompare(b.name));
}

// Go 1.20+ pclntab remains present even when the executable's symbol table is stripped.
function functions(buf, image) {
  const magic = hex(image.arch === 'arm64' ? 'f1ffffff00000408' : 'f1ffffff00000108');
  const candidates = [];
  for (let offset = buf.indexOf(magic); offset >= 0; offset = buf.indexOf(magic, offset + 1)) {
    if (image.pclntab !== undefined && offset !== image.pclntab) continue;
    try {
      const count = u64(buf, offset + 8), text = u64(buf, offset + 24);
      if (!count || count > 1000000) continue;
      if (text) {
        const code = image.toOffset(text);
        if (!image.regions.some(r => r.executable && code >= r.offset && code < r.offset + r.size)) continue;
        if (image.text && text !== image.text) continue;
      } else if (image.format !== 'Mach-O' || !image.regions.some(r => r.executable && offset >= r.offset && offset < r.offset + r.size)) continue;
      bounds(buf, offset + u64(buf, offset + 64), (count + 1) * 8);
      candidates.push(offset);
    } catch { continue; }
  }
  if (candidates.length !== 1) throw new Error('未找到唯一、受支持的 Go 函数表');
  const base = candidates[0];
  bounds(buf, base, 72);
  const count = u64(buf, base + 8);
  if (count > 1000000) throw new Error('无效 Go 函数数量');
  const text = u64(buf, base + 24) || image.text;
  if (!text) throw new Error('无法定位 Go text 基址');
  const names = base + u64(buf, base + 32), table = base + u64(buf, base + 64);
  bounds(buf, table, (count + 1) * 8);
  const result = new Map();
  for (let i = 0; i < count; i++) {
    const meta = table + buf.readUInt32LE(table + i * 8 + 4);
    bounds(buf, meta, 8);
    const nameStart = names + buf.readInt32LE(meta + 4);
    bounds(buf, nameStart, 1);
    const end = buf.indexOf(0, nameStart);
    if (end < 0 || end - nameStart > 4096) throw new Error('无效 Go 函数名称');
    const name = buf.toString('utf8', nameStart, end);
    const tail = name.slice(name.lastIndexOf('/') + 1);
    const key = TARGET_SYMBOLS.has(tail) ? tail : name.endsWith(APPLY_EDITS) ? APPLY_EDITS : null;
    if (key) {
      if (result.has(key)) throw new Error('发现重复 Go 函数符号，拒绝修改');
      const startPc = buf.readUInt32LE(table + i * 8), endPc = buf.readUInt32LE(table + (i + 1) * 8);
      if (endPc < startPc) throw new Error('无效 Go 函数边界');
      const start = image.toOffset(text + startPc, endPc - startPc);
      result.set(key, { start, end: start + endPc - startPc, va: text + startPc });
    }
  }
  return result;
}

function encodeB(pc, target) {
  const delta = target - pc;
  if (delta % 4 !== 0 || delta < -(1 << 27) || delta >= (1 << 27)) {
    throw new Error('ARM64 跳转目标超出指令范围');
  }
  return (0x14000000 | ((delta >> 2) & 0x03ffffff)) >>> 0;
}

function decodeBlTarget(pc, word) {
  if (((word & 0xfc000000) >>> 0) !== 0x94000000) return null;
  let imm26 = word & 0x03ffffff;
  if (imm26 & 0x02000000) imm26 -= 0x04000000;
  return pc + imm26 * 4;
}

function decodeSignedImm19Bytes(word) {
  let imm19 = (word >>> 5) & 0x7ffff;
  if (imm19 & 0x40000) imm19 -= 0x80000;
  return imm19 * 4;
}

function matchGate3aArm64(buf, fn) {
  const hits = [];
  for (let off = fn.start; off <= fn.end - 16; off += 4) {
    const w0 = buf.readUInt32LE(off);
    const w1 = buf.readUInt32LE(off + 4);
    if (((w0 & 0xffe00000) >>> 0) !== 0xd2800000) continue;
    const regLim = w0 & 0x1f;
    if (((w1 & 0xffe0001f) >>> 0) !== ((0xf2a00000 | regLim) >>> 0)) continue;
    const currLim = (((w0 >>> 5) & 0xffff) | (((w1 >>> 5) & 0xffff) << 16)) >>> 0;
    if (currLim < 100000) continue;
    const w2 = buf.readUInt32LE(off + 8);
    const w2Masked = (w2 & 0xfffffc1f) >>> 0;
    const cmp32 = (0x6b00001f | (regLim << 16)) >>> 0;
    const cmp64 = (0xeb00001f | (regLim << 16)) >>> 0;
    if (w2Masked !== cmp32 && w2Masked !== cmp64) continue;
    const regDst = (w2 >>> 5) & 0x1f;
    if (regDst === regLim) continue;

    let wordCount = 4;
    let wLast = buf.readUInt32LE(off + 12);
    if (off + 24 <= fn.end && buf.readUInt32LE(off + 12) === w0 && buf.readUInt32LE(off + 16) === w1) {
      wordCount = 6;
      wLast = buf.readUInt32LE(off + 20);
    }

    const csel64 = (0x9a803000 | (regLim << 16) | (regDst << 5) | regDst) >>> 0;
    const csel32 = (0x1a803000 | (regLim << 16) | (regDst << 5) | regDst) >>> 0;
    let mode = null;
    let cselOp = csel64;
    if (wLast === csel64 || wLast === csel32) {
      cselOp = wLast;
      mode = STOCK_LIMITS.has(currLim) ? 'stock' : currLim === 512000 ? '512k' : currLim === 900000 ? '900k' : null;
    } else if (wLast === NOP_ARM64 && STOCK_LIMITS.has(currLim)) {
      mode = 'dynamic';
    } else {
      continue;
    }

    hits.push({
      id: 'gate3a',
      offset: off,
      length: wordCount * 4,
      mode,
      stockLim: STOCK_LIMITS.has(currLim) ? currLim : 256000,
      cselOp,
      encode(targetMode, saved) {
        const lim = targetMode === 'dynamic' ? (saved.stockLim || 256000) : MODE_LIMITS[targetMode];
        const mw0 = (0xd2800000 | ((lim & 0xffff) << 5) | regLim) >>> 0;
        const mw1 = (0xf2a00000 | (((lim >>> 16) & 0xffff) << 5) | regLim) >>> 0;
        const tailOp = targetMode === 'dynamic' ? NOP_ARM64 : saved.cselOp;
        return wordCount === 6
          ? words(mw0, mw1, w2, mw0, mw1, tailOp)
          : words(mw0, mw1, w2, tailOp);
      }
    });
    off += (wordCount - 1) * 4;
  }
  if (hits.length === 0) return null;
  if (hits.length > 1) throw new Error('上下文补丁状态有歧义');
  if (!hits[0].mode) throw new Error('发现未识别的上下文限制数值，请先恢复官方原版二进制文件');
  return hits[0];
}

function matchGate3aX64(buf, fn) {
  const hits = [];
  for (let off = fn.start; off <= fn.end - 14; off++) {
    if (buf[off] !== 0x81 || buf[off + 1] < 0xf8) continue;
    const regSrc = buf[off + 1] - 0xf8;
    const cmpLim = buf.readUInt32LE(off + 2);
    if (cmpLim < 100000) continue;
    let regDst = null;
    let mode = null;
    if (
      buf[off + 6] >= 0xb8 && buf[off + 6] <= 0xbf &&
      buf.readUInt32LE(off + 7) === cmpLim &&
      buf[off + 11] === 0x0f && buf[off + 12] === 0x42
    ) {
      const candDst = buf[off + 6] - 0xb8;
      if (buf[off + 13] === (0xc0 | (candDst << 3) | regSrc)) {
        regDst = candDst;
        mode = STOCK_LIMITS.has(cmpLim) ? 'stock' : cmpLim === 512000 ? '512k' : cmpLim === 900000 ? '900k' : null;
      }
    } else if (
      STOCK_LIMITS.has(cmpLim) &&
      buf[off + 6] === 0x89 && buf[off + 7] >= 0xc0 &&
      ((buf[off + 7] - 0xc0) >> 3) === regSrc &&
      buf.subarray(off + 8, off + 14).every(b => b === 0x90)
    ) {
      regDst = (buf[off + 7] - 0xc0) & 7;
      mode = 'dynamic';
    }
    if (regDst === null) continue;
    hits.push({
      id: 'gate3a',
      offset: off,
      length: 14,
      mode,
      stockLim: STOCK_LIMITS.has(cmpLim) ? cmpLim : 256000,
      encode(targetMode, saved) {
        const out = Buffer.alloc(14);
        out[0] = 0x81;
        out[1] = 0xf8 + regSrc;
        if (targetMode === 'dynamic') {
          out.writeUInt32LE(saved.stockLim || 256000, 2);
          out[6] = 0x89;
          out[7] = 0xc0 + regSrc * 8 + regDst;
          out.fill(0x90, 8, 14);
        } else {
          const lim = MODE_LIMITS[targetMode];
          out.writeUInt32LE(lim, 2);
          out[6] = 0xb8 + regDst;
          out.writeUInt32LE(lim, 7);
          out[11] = 0x0f;
          out[12] = 0x42;
          out[13] = 0xc0 + regDst * 8 + regSrc;
        }
        return out;
      }
    });
    off += 13;
  }
  if (hits.length === 0) return null;
  if (hits.length > 1) throw new Error('上下文补丁状态有歧义');
  if (!hits[0].mode) throw new Error('发现未识别的上下文限制数值，请先恢复官方原版二进制文件');
  return hits[0];
}

function matchGate3a(buf, image, funcs) {
  const fn = funcs.get(CHECKPOINT);
  if (!fn) return null;
  if (image.arch === 'arm64') return matchGate3aArm64(buf, fn);
  if (image.arch === 'x64') return matchGate3aX64(buf, fn);
  return null;
}

function matchGate3bArm64(buf, fn, funcs) {
  const fnSize = fn.end - fn.start;
  const primaryHits = [];
  for (let rel = 4; rel <= fnSize - 16; rel += 4) {
    const wPrev = buf.readUInt32LE(fn.start + rel - 4);
    if (((wPrev & 0xfc000000) >>> 0) !== 0x94000000) continue;
    const w0 = buf.readUInt32LE(fn.start + rel);
    const op0 = (w0 & 0xff00001f) >>> 0;
    if (op0 !== 0xb4000001 && op0 !== 0xb4000000) continue;
    const span = decodeSignedImm19Bytes(w0);
    if (span < 8 || span > 64 || span % 4 !== 0 || rel + span + 8 > fnSize) continue;
    const wm0 = buf.readUInt32LE(fn.start + rel + span);
    const wm1 = buf.readUInt32LE(fn.start + rel + span + 4);
    if (((wm0 & 0xffc003ff) >>> 0) !== 0xf94003e1 || wm1 !== 0xaa0003e2) continue;
    const unlockedBytes = words(
      (w0 & 0xffffffe0) >>> 0,
      0xb9000c1f,
      ...Array((span - 8) / 4).fill(NOP_ARM64)
    );
    let state = null;
    if (op0 === 0xb4000001) {
      state = 'stock';
    } else if (buf.subarray(fn.start + rel, fn.start + rel + span).equals(unlockedBytes)) {
      state = 'unlocked';
    } else {
      continue;
    }
    primaryHits.push({
      id: 'gate3b',
      offset: fn.start + rel,
      length: span,
      state,
      mode: state,
      encode: () => unlockedBytes
    });
  }
  if (primaryHits.length > 1) throw new Error('上下文补丁状态有歧义');
  if (primaryHits.length === 1) return primaryHits[0];

  const selFn = funcs.get(SELECT_EXP_KEY);
  if (!selFn) return null;
  const fallbackHits = [];
  for (let rel = 0; rel <= fnSize - 16; rel += 4) {
    const w = buf.readUInt32LE(fn.start + rel);
    if (decodeBlTarget(fn.va + rel, w) !== selFn.va) continue;
    const scanEnd = Math.min(rel + 72, fnSize - 4);
    for (let scan = rel + 4; scan < scanEnd; scan += 4) {
      const wb = buf.readUInt32LE(fn.start + scan);
      if (((wb & 0xfffffc1f) >>> 0) !== 0xd63f0000) continue;
      const wn = buf.readUInt32LE(fn.start + scan + 4);
      let state = null;
      if (wn === NOP_ARM64) state = 'unlocked';
      else if (((wn & 0xfffe001f) >>> 0) === 0x37000000 || ((wn & 0x7f00001f) >>> 0) === 0x35000000) state = 'stock';
      else continue;
      const unlockedBytes = words(NOP_ARM64);
      fallbackHits.push({
        id: 'gate3b',
        offset: fn.start + scan + 4,
        length: 4,
        state,
        mode: state,
        encode: () => unlockedBytes
      });
      break;
    }
  }
  if (fallbackHits.length > 1) throw new Error('上下文补丁状态有歧义');
  return fallbackHits[0] || null;
}

function matchGate3bX64(buf, fn, funcs) {
  const selFn = funcs.get(SELECT_EXP_KEY);
  if (!selFn) return null;
  const fnSize = fn.end - fn.start;
  const hits = [];
  const testAl = Buffer.from([0x84, 0xc0]);
  for (let rel = 0; rel <= fnSize - 12; rel++) {
    if (buf[fn.start + rel] !== 0xe8) continue;
    const disp = buf.readInt32LE(fn.start + rel + 1);
    if (fn.va + rel + 5 + disp !== selFn.va) continue;
    const winStart = fn.start + rel + 5;
    const winEnd = Math.min(fn.end, winStart + 100);
    const tIdx = buf.subarray(winStart, winEnd).indexOf(testAl);
    if (tIdx < 0) continue;
    const jSite = winStart + tIdx + 2;
    let len = 0;
    let state = null;
    if (jSite + 6 <= fn.end && buf.subarray(jSite, jSite + 6).every(b => b === 0x90)) {
      len = 6; state = 'unlocked';
    } else if (jSite + 2 <= fn.end && buf[jSite] === 0x90 && buf[jSite + 1] === 0x90) {
      len = 2; state = 'unlocked';
    } else if (jSite + 2 <= fn.end && buf[jSite] === 0x75) {
      len = 2; state = 'stock';
    } else if (jSite + 6 <= fn.end && buf[jSite] === 0x0f && buf[jSite + 1] === 0x85) {
      len = 6; state = 'stock';
    } else {
      continue;
    }
    const unlockedBytes = Buffer.alloc(len, 0x90);
    hits.push({
      id: 'gate3b',
      offset: jSite,
      length: len,
      state,
      mode: state,
      encode: () => unlockedBytes
    });
  }
  if (hits.length > 1) throw new Error('上下文补丁状态有歧义');
  return hits[0] || null;
}

function matchGate3b(buf, image, funcs) {
  const fn = funcs.get(EXP_CHECKPOINT);
  if (!fn) return null;
  if (image.arch === 'arm64') return matchGate3bArm64(buf, fn, funcs);
  if (image.arch === 'x64') return matchGate3bX64(buf, fn, funcs);
  return null;
}

function matchGate1(buf, image, funcs) {
  const fn = funcs.get(OFFERS_CW);
  if (!fn || fn.end - fn.start < 16) return null;
  if (image.arch === 'arm64') {
    const state = buf.subarray(fn.start, fn.start + 8).equals(RET_TRUE_ARM64)
      ? 'unlocked'
      : buf.readUInt32LE(fn.start) !== 0 ? 'stock' : null;
    if (!state) return null;
    return { id: 'gate1', offset: fn.start, length: 8, state, mode: state, encode: () => RET_TRUE_ARM64 };
  }
  if (image.arch === 'x64') {
    const state = buf.subarray(fn.start, fn.start + 6).equals(RET_TRUE_X64)
      ? 'unlocked'
      : buf[fn.start] !== 0 && buf[fn.start] !== 0xcc ? 'stock' : null;
    if (!state) return null;
    return { id: 'gate1', offset: fn.start, length: 6, state, mode: state, encode: () => RET_TRUE_X64 };
  }
  return null;
}

function tryArm64RichGate2(buf, cwFn, choiceFn, ovFn) {
  const cwSize = cwFn.end - cwFn.start;
  if (!ovFn || cwSize < 0x100) return null;
  let ldrX0Sp = null;
  for (let rel = 0; rel < Math.min(0x40, cwSize); rel += 4) {
    const w = buf.readUInt32LE(cwFn.start + rel);
    if (((w & 0xffc003ff) >>> 0) === 0xf90003e0) {
      ldrX0Sp = (0xf94003e0 | (w & 0x003ffc00)) >>> 0;
      break;
    }
  }
  if (ldrX0Sp === null) return null;
  const argonHits = [];
  for (let rel = 0x40; rel < cwSize - 8; rel += 4) {
    const w0 = buf.readUInt32LE(cwFn.start + rel);
    const w1 = buf.readUInt32LE(cwFn.start + rel + 4);
    if (w0 === 0x92800000 && (((w1 & 0xfff8001f) >>> 0) === 0xb7f80000 || w1 === NOP_ARM64)) {
      argonHits.push({ rel: rel + 4, state: w1 === NOP_ARM64 ? 'unlocked' : 'stock' });
    }
  }
  if (argonHits.length !== 1) return null;
  const argonHit = argonHits[0];
  const blHits = [];
  for (let rel = argonHit.rel + 4; rel < cwSize - 24; rel += 4) {
    const w = buf.readUInt32LE(cwFn.start + rel);
    if (decodeBlTarget(cwFn.va + rel, w) === ovFn.va) blHits.push(rel);
  }
  if (blHits.length !== 1) return null;
  const blOvRel = blHits[0];
  const wCbnz = buf.readUInt32LE(cwFn.start + blOvRel + 4);
  if (((wCbnz & 0xff00001f) >>> 0) !== 0xb5000001) return null;
  const epiRel = blOvRel + 4 + decodeSignedImm19Bytes(wCbnz);
  if (epiRel <= 0 || epiRel > cwSize - 12) return null;
  const epiW0 = buf.readUInt32LE(cwFn.start + epiRel);
  const epiW1 = buf.readUInt32LE(cwFn.start + epiRel + 4);
  const epiW2 = buf.readUInt32LE(cwFn.start + epiRel + 8);
  if (epiW2 !== RET_ARM64) return null;
  let tailRel = blOvRel + 8;
  if (buf.readUInt32LE(cwFn.start + tailRel) === NOP_ARM64) tailRel += 4;
  if (tailRel + 16 > epiRel) return null;
  const tailBlob = words(ldrX0Sp, epiW0, epiW1, encodeB(cwFn.va + tailRel + 12, choiceFn.va));
  const nopBlob = words(NOP_ARM64);
  const tailOff = cwFn.start + tailRel;
  const tailState = buf.subarray(tailOff, tailOff + 16).equals(tailBlob) ? 'unlocked' : 'stock';
  return [
    {
      id: 'gate2-whitelist',
      offset: cwFn.start + argonHit.rel,
      length: 4,
      state: argonHit.state,
      mode: argonHit.state,
      encode: () => nopBlob
    },
    {
      id: 'gate2-tail',
      offset: tailOff,
      length: 16,
      state: tailState,
      mode: tailState,
      encode: () => tailBlob
    }
  ];
}

function matchGate2(buf, image, funcs) {
  const cwFn = funcs.get(STORE_CW);
  const choiceFn = funcs.get(STORE_CHOICE);
  if (!cwFn || !choiceFn) return [];
  const cwSize = cwFn.end - cwFn.start;
  if (image.arch === 'arm64') {
    const entryJmp = words(encodeB(cwFn.va, choiceFn.va));
    if (cwSize >= 4 && buf.subarray(cwFn.start, cwFn.start + 4).equals(entryJmp)) {
      return [{ id: 'gate2', offset: cwFn.start, length: 4, state: 'unlocked', mode: 'unlocked', encode: () => entryJmp }];
    }
    const rich = tryArm64RichGate2(buf, cwFn, choiceFn, funcs.get(AUTO_COMPACT_OVERRIDE));
    if (rich) return rich;
    if (cwSize >= 16 && buf.readUInt32LE(cwFn.start) !== 0) {
      return [{ id: 'gate2', offset: cwFn.start, length: 4, state: 'stock', mode: 'stock', encode: () => entryJmp }];
    }
    return [];
  }
  if (image.arch === 'x64') {
    if (cwSize < 16) return [];
    const rel32 = choiceFn.va - (cwFn.va + 5);
    if (rel32 < -0x80000000 || rel32 > 0x7fffffff) {
      throw new Error('Store.ContextWindow x64 跳转目标超出范围');
    }
    const entryJmp = Buffer.alloc(5);
    entryJmp[0] = 0xe9;
    entryJmp.writeInt32LE(rel32, 1);
    const state = buf.subarray(cwFn.start, cwFn.start + 5).equals(entryJmp)
      ? 'unlocked'
      : buf[cwFn.start] !== 0 && buf[cwFn.start] !== 0xcc ? 'stock' : null;
    if (!state) return [];
    return [{ id: 'gate2', offset: cwFn.start, length: 5, state, mode: state, encode: () => entryJmp }];
  }
  return [];
}

function contextGates(buf, image, funcs) {
  const isCli = CLI_SYMS.some(s => funcs.has(s));
  const targetKind = isCli ? 'cli' : 'server';
  const gates = [];

  if (isCli) {
    const g1 = matchGate1(buf, image, funcs);
    const g2 = matchGate2(buf, image, funcs);
    const g3a = matchGate3a(buf, image, funcs);
    const g3b = matchGate3b(buf, image, funcs);
    if (g1) gates.push(g1);
    gates.push(...g2);
    if (g3a) gates.push(g3a);
    if (g3b) gates.push(g3b);

    const hasAll = Boolean(
      CLI_SYMS.every(s => funcs.has(s)) &&
      funcs.has(CHECKPOINT) &&
      funcs.has(EXP_CHECKPOINT) &&
      g1 && g2.length > 0 && g3a && g3b
    );
    if (!hasAll) {
      return {
        supported: false,
        targetKind,
        mode: 'unknown',
        reason: '此版本缺少完整、唯一的已知 CLI 上下文指令特征，未修改任何限制',
        gates
      };
    }

    const limitMode = g3a.mode;
    const expectedState = limitMode === 'stock' ? 'stock' : 'unlocked';
    const boolGates = [g1, ...g2, g3b];
    if (boolGates.some(g => g.state !== expectedState)) {
      return {
        supported: false,
        targetKind,
        mode: 'unknown',
        reason: '上下文补丁状态不一致，请先恢复官方原版二进制文件',
        gates
      };
    }
    for (const g of boolGates) g.mode = limitMode;
    return { supported: true, targetKind, mode: limitMode, gates };
  }

  const g3a = matchGate3a(buf, image, funcs);
  const g3b = matchGate3b(buf, image, funcs);
  if (g3a) gates.push(g3a);
  if (g3b) gates.push(g3b);
  const legacyIdePe = !funcs.has(EXP_CHECKPOINT) && image.format === 'PE' && Boolean(g3a && g3a.stockLim === 128000);
  const supported = Boolean(g3a && (g3b || legacyIdePe));
  if (!supported) {
    return {
      supported: false,
      targetKind,
      mode: 'unknown',
      reason: '此版本缺少完整、唯一的已知上下文指令特征，未修改任何限制',
      gates
    };
  }
  const limitMode = g3a.mode;
  const expectedState = limitMode === 'stock' ? 'stock' : 'unlocked';
  if (g3b && g3b.state !== expectedState) {
    return {
      supported: false,
      targetKind,
      mode: 'unknown',
      reason: '上下文补丁状态不一致，请先恢复官方原版二进制文件',
      gates
    };
  }
  if (g3b) g3b.mode = limitMode;
  return { supported: true, targetKind, mode: limitMode, gates };
}

function guardPatch(buf, image, funcs) {
  const range = funcs.get(APPLY_EDITS);
  if (!range) return null;
  if (image.arch !== 'x64') throw new Error('此版本的提示词初始化校验尚不支持修改');
  const prefix = hex('488b71104889742458488b711848897424384889d1');
  const offset = unique(buf, prefix, range.start, range.end);
  if (offset < 0 || buf[offset + prefix.length] !== 0xe8) throw new Error('无法识别提示词初始化校验');
  const tail = offset + prefix.length + 5;
  const variants = [hex('4883f8010f8474ffffff'), hex('4883f801e975ffffff90')];
  if (!variants.some(v => buf.subarray(tail, tail + v.length).equals(v))) throw new Error('未知提示词初始化校验状态');
  return { offset: tail, variants };
}

function inspect(buf) {
  const image = layout(buf);
  const slots = templateSlots(buf, image);
  let funcs = new Map(), context;
  try {
    funcs = functions(buf, image);
    context = contextGates(buf, image, funcs);
  } catch (error) {
    context = { supported: false, targetKind: 'server', mode: 'unknown', reason: error.message, gates: [] };
  }
  // Unknown Go metadata also prevents reliably checking startup template edits.
  let promptError;
  try {
    if (!funcs.size) throw new Error('无法验证提示词初始化函数，禁止修改');
    guardPatch(buf, image, funcs);
  } catch (error) { promptError = error.message; }
  return { image, slots, funcs, context, promptError };
}

export function inspectBinary(buf) {
  const { image, slots, context, promptError } = inspect(buf);
  return { format: image.format, arch: image.arch,
    context: {
      supported: context.supported,
      targetKind: context.targetKind,
      mode: context.mode,
      ...(context.reason ? { reason: context.reason } : {}),
      gates: context.gates.map(({ id, mode, offset }) => ({ id, mode, offset }))
    },
    templates: slots.map(({ offset, ...slot }) => ({ ...slot, editable: slot.editable && !promptError })),
    warning: promptError };
}

export function patchBinary(buf, options, original = buf) {
  if (options.restoreAll) return Buffer.from(original);
  const current = inspect(buf), baseline = inspect(original);
  if (current.image.format !== baseline.image.format || current.image.arch !== baseline.image.arch) throw new Error('备份格式不匹配');
  const operations = [];
  if (options.contextMode !== undefined) {
    if (!MODES.includes(options.contextMode)) throw new Error('无效上下文模式');
    if (!current.context.supported || !baseline.context.supported) throw new Error(current.context.reason || '备份上下文特征不受支持');
    if (current.context.targetKind !== baseline.context.targetKind) throw new Error('备份目标类型不匹配');
    if (options.contextMode === 'stock' && baseline.context.mode !== 'stock') {
      throw new Error('缺少原生备份，无法恢复原生上下文指令');
    }
    for (const gate of current.context.gates) {
      const saved = baseline.context.gates.find(g => g.id === gate.id && g.offset === gate.offset && g.length === gate.length);
      if (!saved) throw new Error('备份补丁位置不匹配');
      const bytes = options.contextMode === 'stock'
        ? original.subarray(saved.offset, saved.offset + saved.length)
        : gate.encode(options.contextMode, saved);
      if (bytes.length !== gate.length) throw new Error('补丁长度不匹配，拒绝修改');
      operations.push({ offset: gate.offset, bytes });
    }
  }
  const changingPrompts = options.templates !== undefined || options.restorePrompts;
  if (changingPrompts) {
    if (current.promptError) throw new Error(current.promptError);
    if (options.templates !== undefined && (!options.templates || Array.isArray(options.templates) || typeof options.templates !== 'object')) throw new Error('无效提示词模板');
    if (options.restorePrompts) {
      for (const slot of current.slots) {
        if (!slot.editable) continue;
        const saved = baseline.slots.find(s => s.name === slot.name && s.offset === slot.offset && s.capacity === slot.capacity);
        if (!saved) throw new Error('备份模板布局不匹配');
        operations.push({ offset: slot.offset, bytes: original.subarray(saved.offset, saved.offset + saved.capacity) });
      }
    }
    for (const [name, content] of Object.entries(options.templates || {})) {
      const slot = current.slots.find(s => s.name === name);
      if (!slot || !slot.editable) throw new Error(`不允许修改模板: ${name}`);
      if (typeof content !== 'string' || content.includes('\0')) throw new Error('提示词必须是无 NUL 的文本');
      if (content === slot.content) continue;
      // Custom text is deliberately literal. Executable Go template expressions
      // would require the host's private FuncMap to validate and can panic at boot.
      if (content.includes('{{') || content.includes('}}')) throw new Error('自定义提示词仅接受纯文本，请移除 Go 模板指令 {{…}}；恢复原版请使用恢复按钮');
      const encoded = Buffer.from(content);
      if (encoded.length > slot.capacity) throw new Error(`${name}: ${encoded.length} 字节超出槽位容量 ${slot.capacity}`);
      const bytes = Buffer.alloc(slot.capacity, ' ');
      encoded.copy(bytes);
      const remaining = slot.capacity - encoded.length;
      if (remaining >= 8) {
        bytes.write('{{/*', encoded.length);
        bytes.write('*/}}', slot.capacity - 4);
      }
      operations.push({ offset: slot.offset, bytes });
    }
  }
  const result = Buffer.from(buf);
  for (const { offset, bytes } of operations) bytes.copy(result, offset);
  if (changingPrompts) {
    const guard = guardPatch(buf, current.image, current.funcs);
    if (guard) {
      const modified = current.slots.some(slot => {
        const saved = baseline.slots.find(s => s.name === slot.name);
        return !saved || !result.subarray(slot.offset, slot.offset + slot.capacity).equals(original.subarray(saved.offset, saved.offset + saved.capacity));
      });
      const source = modified ? guard.variants[1] : original.subarray(guard.offset, guard.offset + guard.variants[0].length);
      source.copy(result, guard.offset);
    }
  }
  const identity = current.slots.find(slot => slot.name === 'identity.tmpl');
  if (!result.subarray(identity.offset, identity.offset + identity.capacity).equals(buf.subarray(identity.offset, identity.offset + identity.capacity))) {
    throw new Error('修改与身份模板重叠，拒绝写入');
  }
  return result;
}
