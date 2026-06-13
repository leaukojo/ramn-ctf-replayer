const BAUD_RATE = 115200;
const DZZ_CMD = 'DzZ\r';
const SELFDESTRUCT_CMD = 'selfdestruct\r';
const WAIT_MS = 1500;

let serialPort = null;
let serialWriter = null;
let serialReader = null;

const _onAndroid = /Android/i.test(navigator.userAgent);
const SERIAL_USB_FILTERS = [
  {vendorId: 0x0483, productId: 0x5740},
  {vendorId: 0x1d50, productId: 0x606f}
];

function logSerial(msg, type = 'info') {
  const log = document.getElementById('serial-log');
  const line = document.createElement('div');
  line.className = 'log-line log-' + type;
  line.textContent = msg;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function clearSerialLog() {
  document.getElementById('serial-log').innerHTML = '';
}

async function writeSerial(writer, text) {
  const encoded = new TextEncoder().encode(text);
  await writer.write(encoded);
}

async function readWithTimeout(reader, timeoutMs) {
  let accumulated = '';
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const remaining = deadline - Date.now();
    const timeoutPromise = new Promise(resolve => setTimeout(() => resolve(null), remaining));
    let result;
    try {
      result = await Promise.race([reader.read(), timeoutPromise]);
    } catch (_) {
      break; // device disconnected (standard firmware enters DFU) or read failed
    }
    if (result === null) break; // timeout
    if (result.done) break;
    accumulated += new TextDecoder().decode(result.value);
  }
  return accumulated;
}

// Read loop for WebUSB path with a wall-clock timeout.
// Pending transferIn is abandoned (cleaned up when device closes).
async function usbReadWithTimeout(dev, inEp, timeoutMs) {
  let accumulated = '';
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const remaining = deadline - Date.now();
    let result;
    try {
      result = await Promise.race([
        dev.transferIn(inEp, 64),
        new Promise(r => setTimeout(() => r(null), remaining))
      ]);
    } catch (_) {
      break; // device disconnected (standard firmware enters DFU) or transfer failed
    }
    if (result === null) break;
    if (result.data && result.data.byteLength > 0)
      accumulated += new TextDecoder().decode(result.data);
  }
  return accumulated;
}

// Opens the RAMN CDC-ACM device via WebUSB and returns {dev, data, inEp, outEp}.
// Used on Android where Web Serial cannot enumerate composite USB devices.
async function openWebUSBCDC() {
  const dev = await navigator.usb.requestDevice({filters: SERIAL_USB_FILTERS});
  await dev.open();
  if (dev.configuration === null) await dev.selectConfiguration(1);
  let ctrl = null, data = null, inEp = null, outEp = null;
  for (const ifc of dev.configuration.interfaces) {
    const alt = ifc.alternates[0];
    if (alt.interfaceClass === 0x02 && alt.interfaceSubclass === 0x02)
      ctrl = ifc.interfaceNumber;
    if (alt.interfaceClass === 0x0A) {
      data = ifc.interfaceNumber;
      for (const ep of alt.endpoints) {
        if (ep.direction === 'in')  inEp  = ep.endpointNumber;
        if (ep.direction === 'out') outEp = ep.endpointNumber;
      }
    }
  }
  if (data === null) throw new Error('CDC-ACM data interface not found');
  if (ctrl !== null) await dev.claimInterface(ctrl);
  await dev.claimInterface(data);
  if (ctrl !== null) {
    // SET_LINE_CODING: 115200 baud, 1 stop bit, no parity, 8 data bits
    const coding = new ArrayBuffer(7);
    const v = new DataView(coding);
    v.setUint32(0, 115200, true); v.setUint8(4, 0); v.setUint8(5, 0); v.setUint8(6, 8);
    await dev.controlTransferOut(
      {requestType: 'class', recipient: 'interface', request: 0x20, value: 0, index: ctrl},
      coding
    );
    // SET_CONTROL_LINE_STATE: assert DTR + RTS
    await dev.controlTransferOut(
      {requestType: 'class', recipient: 'interface', request: 0x22, value: 0x03, index: ctrl}
    );
  }
  return {dev, data, inEp, outEp};
}

async function closeSerial() {
  try { if (serialReader) { await serialReader.cancel(); serialReader.releaseLock(); } } catch (_) {}
  try { if (serialWriter) { serialWriter.releaseLock(); } } catch (_) {}
  try { if (serialPort) { await serialPort.close(); } } catch (_) {}
  serialReader = null;
  serialWriter = null;
  serialPort = null;
}

async function runBoardReset() {
  const btn = document.getElementById('reset-btn');
  const resultEl = document.getElementById('reset-result');
  btn.disabled = true;
  resultEl.innerHTML = '';
  clearSerialLog();

  const hasSerial = 'serial' in navigator;
  const hasAndroidUSB = _onAndroid && 'usb' in navigator;

  if (!hasSerial && !hasAndroidUSB) {
    logSerial('Web Serial is not supported in this browser. Use Chrome or Edge.', 'error');
    btn.disabled = false;
    return;
  }

  let usbDev = null;
  let removeDisconnectListener = () => {};
  try {
    if (hasAndroidUSB) {
      logSerial('Android detected — using WebUSB path…');
      logSerial('Requesting USB device…');
      const {dev, inEp, outEp} = await openWebUSBCDC();
      usbDev = dev;
      logSerial(`Device opened at ${BAUD_RATE} baud.`, 'ok');

      let disconnected = false;
      const onDisconnect = (e) => { if (e.device === usbDev) disconnected = true; };
      navigator.usb.addEventListener('disconnect', onDisconnect);
      removeDisconnectListener = () => navigator.usb.removeEventListener('disconnect', onDisconnect);

      logSerial(`Sending: DzZ\\r`);
      await usbDev.transferOut(outEp, new TextEncoder().encode(DZZ_CMD));
      const resp1 = await usbReadWithTimeout(usbDev, inEp, WAIT_MS);
      if (resp1.trim().length > 0) logSerial(`Response: ${resp1.trim()}`, 'ok');

      // Standard firmware enters DFU on DzZ and the device drops off the bus.
      // ESV CTF firmware answers DzZ but stays up — send selfdestruct to enter DFU.
      if (!disconnected) {
        logSerial('Device still present — sending selfdestruct (ESV firmware)…', 'warn');
        try {
          await usbDev.transferOut(outEp, new TextEncoder().encode(SELFDESTRUCT_CMD));
          const resp2 = await usbReadWithTimeout(usbDev, inEp, WAIT_MS);
          if (resp2.trim().length > 0) logSerial(`Response: ${resp2.trim()}`, 'ok');
        } catch (_) { /* device dropped off mid-command — expected on entering DFU */ }
      }

      logSerial('ECU A should now be in DFU mode.', 'ok');
      try { await usbDev.close(); } catch (_) {}
      usbDev = null;
    } else {
      logSerial('Requesting serial port…');
      serialPort = await navigator.serial.requestPort();
      await serialPort.open({ baudRate: BAUD_RATE });
      logSerial(`Port opened at ${BAUD_RATE} baud.`, 'ok');

      let disconnected = false;
      const onDisconnect = (e) => { if (e.target === serialPort) disconnected = true; };
      navigator.serial.addEventListener('disconnect', onDisconnect);
      removeDisconnectListener = () => navigator.serial.removeEventListener('disconnect', onDisconnect);

      serialWriter = serialPort.writable.getWriter();
      serialReader = serialPort.readable.getReader();

      logSerial(`Sending: DzZ\\r`);
      await writeSerial(serialWriter, DZZ_CMD);
      const resp1 = await readWithTimeout(serialReader, WAIT_MS);
      if (resp1.trim().length > 0) logSerial(`Response: ${resp1.trim()}`, 'ok');

      // Standard firmware enters DFU on DzZ and the serial port disconnects.
      // ESV CTF firmware answers DzZ but stays up — send selfdestruct to enter DFU.
      if (!disconnected && serialPort.connected !== false) {
        logSerial('Port still alive — sending selfdestruct (ESV firmware)…', 'warn');
        try {
          await writeSerial(serialWriter, SELFDESTRUCT_CMD);
          const resp2 = await readWithTimeout(serialReader, WAIT_MS);
          if (resp2.trim().length > 0) logSerial(`Response: ${resp2.trim()}`, 'ok');
        } catch (_) { /* port dropped mid-command — expected on entering DFU */ }
      }

      logSerial('ECU A should now be in DFU mode.', 'ok');
      await closeSerial();
    }

    const flashUrl = `${FLASHER_URL}/#newboard`;
    resultEl.innerHTML = `
      <div class="reset-success">
        <strong>ECU A is in DFU mode.</strong><br>
        Now open <a href="${flashUrl}" target="_blank">ramn-flasher</a> to reflash standard firmware.
      </div>
    `;
  } catch (err) {
    logSerial(`Error: ${err.message}`, 'error');
    if (usbDev) { try { await usbDev.close(); } catch (_) {} }
    else { await closeSerial(); }
  } finally {
    removeDisconnectListener();
  }

  btn.disabled = false;
}

function initSerial() {
  const btn = document.getElementById('reset-btn');
  btn.addEventListener('click', runBoardReset);

  const hasSerial = 'serial' in navigator;
  const hasAndroidUSB = _onAndroid && 'usb' in navigator;

  if (!hasSerial && !hasAndroidUSB) {
    btn.disabled = true;
    btn.title = 'Web Serial requires Chrome or Edge';
    logSerial('Web Serial not available. Use Chrome or Edge, served over localhost or HTTPS.', 'warn');
  }
}
