// Format-aware, fixed-size patches. Reference signatures: justhil/agy-tool
// (https://github.com/justhil/agy-tool); ARM64 patterns inspected on desktop 2.32.1.
// Never search/replace numeric limits globally: every code patch is scoped to
// its Go function and requires an exact, unique instruction sequence.
const PREFIX = 'google3/third_party/jetski/prompt/template_provider/templates/system_prompts/';
const CHECKPOINT = 'google3/third_party/jetski/cortex/utils/utils.GetCheckpointConfig';
const SERIALIZER = 'google3/third_party/oneharness/internal/core/serializers/serializers.DefaultSerializer.populateContextWindowMetadata';
const MODES = ['stock', '512k', '900k'];
const hex = value => Buffer.from(value.replaceAll(' ', ''), 'hex');
const words = (...values) => {
  const result = Buffer.alloc(values.length * 4);
  values.forEach((value, i) => result.writeUInt32LE(value >>> 0, i * 4));
  return result;
};

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
    arch = buf.readUInt16LE(pe + 4) === 0x8664 ? 'x64' : 'unknown';
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
    if (name === CHECKPOINT || name === SERIALIZER || name.endsWith('genericsystemprompt.applyEdits')) {
      const startPc = buf.readUInt32LE(table + i * 8), endPc = buf.readUInt32LE(table + (i + 1) * 8);
      const start = image.toOffset(text + startPc, endPc - startPc);
      result.set(name, { start, end: start + endPc - startPc });
    }
  }
  return result;
}

const X64 = [
  ['main', CHECKPOINT, '8b54244c81fa00e80300be00e803000f42f289742450', '8b54244c81fa00d00700be00d007000f42f289742450', '8b54244c81fa00e8030089d690909090909089742450'],
  ['fallback', CHECKPOINT, '837a14007f07c7400c00e80300', '837a14007f07c7400c00d00700', '837a14007f07c7400ca0bb0d00'],
  ['display', SERIALIZER, '4889442470488b8c24a80100008908b830000000', '4889442470c70000d0070090909090b830000000', '4889442470c70000000f0090909090b830000000'],
  ['ide-main', CHECKPOINT, '8b4c245429d181f900f40100ba00f401000f42d18954244c', '8b4c245429d181f900d00700ba00d007000f42d18954244c', '8b4c245429d181f900f4010089ca9090909090908954244c']
];
const ARM = [
  ['main', CHECKPOINT,
    words(0xb94057e3, 0xd29d0004, 0xf2a00064, 0x6b04007f, 0xd29d0004, 0xf2a00064, 0x9a843063, 0xb9005be3),
    words(0xb94057e3, 0xd29a0004, 0xf2a000e4, 0x6b04007f, 0xd29a0004, 0xf2a000e4, 0x9a843063, 0xb9005be3),
    words(0xb94057e3, 0xd29d0004, 0xf2a00064, 0x6b04007f, 0xd29d0004, 0xf2a00064, 0xd503201f, 0xb9005be3)],
  ['fallback', CHECKPOINT,
    words(0x7100007f, 0x5400008c, 0xd29d0003, 0xf2a00063, 0xb9000c03),
    words(0x7100007f, 0x5400008c, 0xd29a0003, 0xf2a000e3, 0xb9000c03),
    words(0x7100007f, 0x5400008c, 0xd2977403, 0xf2a001a3, 0xb9000c03)]
];

function matchGate(buf, range, id, variants) {
  if (!range) return null;
  const hits = [];
  variants.forEach((bytes, index) => {
    const offset = unique(buf, bytes, range.start, range.end);
    if (offset >= 0) hits.push({ id, offset, mode: MODES[index], variants });
  });
  if (hits.length > 1) throw new Error('上下文补丁状态有歧义');
  return hits[0] || null;
}

function contextGates(buf, image, funcs) {
  const specs = image.arch === 'x64' ? X64.map(([id, fn, ...bytes]) => [id, fn, ...bytes.map(hex)])
    : image.format === 'Mach-O' && image.arch === 'arm64' ? ARM : [];
  const gates = specs.map(([id, fn, ...variants]) => matchGate(buf, funcs.get(fn), id, variants)).filter(Boolean);
  if (image.format === 'Mach-O' && image.arch === 'arm64') {
    const range = funcs.get(SERIALIZER);
    if (range && range.end - range.start > 12) {
      // A literal in unreachable alignment padding lets one LDR load either
      // display limit without moving instructions or truncating 512,000.
      const cave = range.end - 4;
      const branch = buf.readUInt32LE(cave - 4);
      const imm26 = (branch & 0x3ffffff) << 6 >> 6;
      if ((branch >>> 26) === 5 && cave - 4 + imm26 * 4 === range.start) {
        const prefix = words(0xf90043e0);
        const p = unique(buf, prefix, range.start, range.end);
        if (p >= 0) {
          const displacement = cave - (p + 4);
          if (displacement % 4 === 0 && displacement < 1048576 && displacement > -1048576) {
            const load = (0x18000001 | (((displacement / 4) & 0x7ffff) << 5)) >>> 0;
            const variants = [words(0xf90043e0, 0xf940dfe1, 0xb9000001, 0xb27c07e0),
              words(0xf90043e0, load, 0xb9000001, 0xb27c07e0)];
            const stock = buf.subarray(p, p + 16).equals(variants[0]);
            const patched = buf.subarray(p, p + 16).equals(variants[1]);
            const literal = buf.readUInt32LE(cave);
            const mode = stock && literal === 0 ? 'stock' : patched && literal === 512000 ? '512k' : patched && literal === 983040 ? '900k' : null;
            if (mode) {
              gates.push({ id: 'display', mode, offset: p, variants: [variants[0], variants[1], variants[1]] });
              gates.push({ id: 'display-literal', mode, offset: cave, variants: [words(0), words(512000), words(983040)] });
            }
          }
        }
      }
    }
  }
  const ids = gates.map(g => g.id);
  const desktop = ['main', 'fallback', 'display'].every(id => ids.includes(id));
  const ide = image.format === 'PE' && ids.length === 1 && ids[0] === 'ide-main';
  const supported = desktop || ide;
  const modes = new Set(gates.map(g => g.mode));
  return { supported, mode: supported && modes.size === 1 ? gates[0].mode : 'unknown',
    reason: supported ? undefined : '此版本缺少完整、唯一的已知上下文指令特征，未修改任何限制', gates };
}

function guardPatch(buf, image, funcs) {
  const name = [...funcs.keys()].find(name => name.endsWith('genericsystemprompt.applyEdits'));
  if (!name) return null;
  if (image.arch !== 'x64') throw new Error('此版本的提示词初始化校验尚不支持修改');
  const range = funcs.get(name);
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
    context = { supported: false, mode: 'unknown', reason: error.message, gates: [] };
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
    context: { ...context, gates: context.gates.map(({ id, mode, offset }) => ({ id, mode, offset })) },
    templates: slots.map(({ offset, ...slot }) => ({ ...slot, editable: slot.editable && !promptError })),
    warning: promptError };
}

export function patchBinary(buf, options, original = buf) {
  if (options.restoreAll) return Buffer.from(original);
  const current = inspect(buf), baseline = inspect(original);
  if (current.image.format !== baseline.image.format || current.image.arch !== baseline.image.arch) throw new Error('备份格式不匹配');
  const operations = [];
  if (options.contextMode !== undefined) {
    const index = MODES.indexOf(options.contextMode);
    if (index < 0) throw new Error('无效上下文模式');
    if (!current.context.supported || !baseline.context.supported) throw new Error(current.context.reason || '备份上下文特征不受支持');
    for (const gate of current.context.gates) {
      const saved = baseline.context.gates.find(g => g.id === gate.id && g.offset === gate.offset);
      if (!saved) throw new Error('备份补丁位置不匹配');
      operations.push({ offset: gate.offset, bytes: gate.variants[index] });
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
