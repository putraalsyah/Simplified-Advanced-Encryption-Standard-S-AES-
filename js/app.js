/**
 * app.js
 * ------------------------------------------------------------
 * Menghubungkan form (index.html) dengan mesin S-AES (saes-core.js)
 * dan merender seluruh langkah perhitungan ke dalam DOM.
 * ------------------------------------------------------------ */

document.addEventListener('DOMContentLoaded', () => {

  const form = document.getElementById('saes-form');
  const inputField = document.getElementById('input-bits');
  const keyField = document.getElementById('key-bits');
  const modeRadios = document.getElementsByName('mode');
  const resetBtn = document.getElementById('reset-btn');
  const inputLabel = document.getElementById('input-label');

  const outputSection = document.getElementById('output-section');
  const outputBin = document.getElementById('output-bin');
  const outputHex = document.getElementById('output-hex');
  const outputCaption = document.getElementById('output-caption');

  const stepsToggle = document.getElementById('steps-toggle');
  const stepsContainer = document.getElementById('steps-container');
  const errorBox = document.getElementById('error-box');

  const S = SAES;

  // -----------------------------------------------------------
  // Render tabel referensi statis (S-Box, InvS-Box, RCON, Matriks)
  // -----------------------------------------------------------
  function renderRefTables() {
    const sboxTable = document.getElementById('sbox-table');
    const invSboxTable = document.getElementById('invsbox-table');
    sboxTable.innerHTML = buildLookupTable(S.SBOX);
    invSboxTable.innerHTML = buildLookupTable(S.INV_SBOX);
  }

  function buildLookupTable(box) {
    let head = '<tr><th>Input (hex)</th>' + box.map((_, i) => `<th>${S.nib2hex(i)}</th>`).join('') + '</tr>';
    let body = '<tr><th>Output (hex)</th>' + box.map((v) => `<td>${S.nib2hex(v)}</td>`).join('') + '</tr>';
    return head + body;
  }

  // -----------------------------------------------------------
  // Helper render matriks state 2x2 (nibble -> kotak biner+hex)
  // -----------------------------------------------------------
  function nibbleCell(n, highlight = false) {
    return `<div class="nibble-cell ${highlight ? 'nibble-cell--hl' : ''}">
              <span class="nibble-hex">${S.nib2hex(n)}</span>
              <span class="nibble-bin">${S.nib2bin(n)}</span>
            </div>`;
  }

  function stateMatrixHTML(nibbles, title) {
    const m = S.stateMatrixView(nibbles);
    return `
      <div class="state-block">
        ${title ? `<div class="state-block__title">${title}</div>` : ''}
        <div class="state-matrix">
          ${nibbleCell(m[0][0])}${nibbleCell(m[0][1])}
          ${nibbleCell(m[1][0])}${nibbleCell(m[1][1])}
        </div>
      </div>`;
  }

  function wordHTML(label, word) {
    return `<div class="word-chip"><span class="word-chip__label">${label}</span>
              <span class="word-chip__val">${word.map(S.nib2hex).join(' ')}
              <em>(${word.map(S.nib2bin).join(' ')})</em></span></div>`;
  }

  // -----------------------------------------------------------
  // Render satu blok "before -> after" untuk transformasi sederhana
  // -----------------------------------------------------------
  function beforeAfterBlock(title, before, after, note = '') {
    return `
      <div class="step-card">
        <h4>${title}</h4>
        ${note ? `<p class="step-note">${note}</p>` : ''}
        <div class="ba-row">
          ${stateMatrixHTML(before, 'Sebelum')}
          <div class="ba-arrow">&rarr;</div>
          ${stateMatrixHTML(after, 'Sesudah')}
        </div>
      </div>`;
  }

  function addRoundKeyBlock(step) {
    return `
      <div class="step-card">
        <h4>${step.label}</h4>
        <div class="ba-row ba-row--3">
          ${stateMatrixHTML(step.before, 'State')}
          <div class="ba-arrow">XOR</div>
          ${stateMatrixHTML(step.key, 'Round Key')}
          <div class="ba-arrow">=</div>
          ${stateMatrixHTML(step.after, 'Hasil')}
        </div>
      </div>`;
  }

  function gfTraceHTML(label, a, b, mtrace) {
    const rows = mtrace.trace.map(t => `
      <tr>
        <td>${t.i}</td><td>${t.x}</td><td>${t.yBit}</td>
        <td>${t.carryReduce ? 'ya (XOR 0x13)' : 'tidak'}</td><td>${t.pAfter}</td>
      </tr>`).join('');
    return `
      <details class="gf-trace">
        <summary>${label}: ${S.nib2hex(a)} &times; ${S.nib2hex(b)} = ${S.nib2hex(mtrace.result)} (lihat langkah GF)</summary>
        <table class="gf-trace-table">
          <thead><tr><th>i</th><th>x saat ini</th><th>bit y</th><th>reduksi?</th><th>p sementara</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </details>`;
  }

  function mixColumnsBlock(step, matrixLabel) {
    const d = step.detail;
    return `
      <div class="step-card">
        <h4>${matrixLabel} - Round ${step.round}</h4>
        <div class="ba-row">
          ${stateMatrixHTML(step.before, 'Sebelum')}
          <div class="ba-arrow">&rarr;</div>
          ${stateMatrixHTML(step.after, 'Sesudah')}
        </div>
        <p class="step-note">Matriks pengali: | ${d.matrix[0][0]} ${d.matrix[0][1]} | / | ${d.matrix[1][0]} ${d.matrix[1][1]} | (GF(2^4), mod x^4+x+1 / 0x13)</p>
        <div class="gf-col">
          <strong>Kolom 1</strong> [${d.col1.map(S.nib2hex).join(', ')}]
          ${gfTraceHTML(`${d.matrix[0][0]}·c0`, d.matrix[0][0], d.col1[0], d.r1.m00)}
          ${gfTraceHTML(`${d.matrix[0][1]}·c1`, d.matrix[0][1], d.col1[1], d.r1.m01)}
          ${gfTraceHTML(`${d.matrix[1][0]}·c0`, d.matrix[1][0], d.col1[0], d.r1.m10)}
          ${gfTraceHTML(`${d.matrix[1][1]}·c1`, d.matrix[1][1], d.col1[1], d.r1.m11)}
        </div>
        <div class="gf-col">
          <strong>Kolom 2</strong> [${d.col2.map(S.nib2hex).join(', ')}]
          ${gfTraceHTML(`${d.matrix[0][0]}·c0`, d.matrix[0][0], d.col2[0], d.r2.m00)}
          ${gfTraceHTML(`${d.matrix[0][1]}·c1`, d.matrix[0][1], d.col2[1], d.r2.m01)}
          ${gfTraceHTML(`${d.matrix[1][0]}·c0`, d.matrix[1][0], d.col2[0], d.r2.m10)}
          ${gfTraceHTML(`${d.matrix[1][1]}·c1`, d.matrix[1][1], d.col2[1], d.r2.m11)}
        </div>
      </div>`;
  }

  function keyExpansionBlock(log) {
    return `
      <div class="step-card">
        <h4>Key Expansion</h4>
        <div class="word-grid">
          ${wordHTML('w0', log.w0)}
          ${wordHTML('w1', log.w1)}
        </div>
        <p class="step-note">w2 = w0 &oplus; SubWord(RotWord(w1)) &oplus; RCON1</p>
        <div class="word-grid">
          ${wordHTML('RotWord(w1)', log.rotW1)}
          ${wordHTML('SubWord(RotWord(w1))', log.subRotW1)}
          ${wordHTML('RCON1', log.RCON1)}
          ${wordHTML('g1 = SubWord(RotWord(w1)) ⊕ RCON1', log.g1)}
          ${wordHTML('w2 = w0 ⊕ g1', log.w2)}
        </div>
        <p class="step-note">w3 = w2 &oplus; w1</p>
        <div class="word-grid">${wordHTML('w3', log.w3)}</div>
        <p class="step-note">w4 = w2 &oplus; SubWord(RotWord(w3)) &oplus; RCON2</p>
        <div class="word-grid">
          ${wordHTML('RotWord(w3)', log.rotW3)}
          ${wordHTML('SubWord(RotWord(w3))', log.subRotW3)}
          ${wordHTML('RCON2', log.RCON2)}
          ${wordHTML('g2 = SubWord(RotWord(w3)) ⊕ RCON2', log.g2)}
          ${wordHTML('w4 = w2 ⊕ g2', log.w4)}
        </div>
        <p class="step-note">w5 = w4 &oplus; w3</p>
        <div class="word-grid">${wordHTML('w5', log.w5)}</div>
        <hr/>
        <div class="word-grid word-grid--keys">
          ${wordHTML('K0 = w0 || w1', log.K0)}
          ${wordHTML('K1 = w2 || w3', log.K1)}
          ${wordHTML('K2 = w4 || w5', log.K2)}
        </div>
      </div>`;
  }

  // -----------------------------------------------------------
  // Render seluruh langkah sesuai tipe step yang dihasilkan saes-core.js
  // -----------------------------------------------------------
  function renderSteps(steps) {
    let html = '';
    steps.forEach((step) => {
      switch (step.type) {
        case 'keyExpansion':
          html += keyExpansionBlock(step.data);
          break;
        case 'input':
          html += `<div class="step-card step-card--io">
                      <h4>${step.label}</h4>
                      ${stateMatrixHTML(step.state)}
                    </div>`;
          break;
        case 'addRoundKey':
          html += addRoundKeyBlock(step);
          break;
        case 'subNibbles':
          html += beforeAfterBlock(`SubNibbles - Round ${step.round} (${step.box})`, step.before, step.after,
            'Setiap nibble disubstitusi memakai S-Box.');
          break;
        case 'invSubNibbles':
          html += beforeAfterBlock(`InvSubNibbles - Round ${step.round} (${step.box})`, step.before, step.after,
            'Setiap nibble disubstitusi memakai Inverse S-Box.');
          break;
        case 'shiftRows':
          html += beforeAfterBlock(`ShiftRows - Round ${step.round}`, step.before, step.after,
            'Baris kedua matriks state ditukar (digeser 1 nibble).');
          break;
        case 'invShiftRows':
          html += beforeAfterBlock(`InvShiftRows - Round ${step.round}`, step.before, step.after,
            'ShiftRows bersifat self-inverse, sehingga operasinya identik dengan ShiftRows.');
          break;
        case 'mixColumns':
          html += mixColumnsBlock(step, 'MixColumns');
          break;
        case 'invMixColumns':
          html += mixColumnsBlock(step, 'InvMixColumns');
          break;
        case 'output':
          html += `<div class="step-card step-card--io step-card--final">
                      <h4>${step.label}</h4>
                      ${stateMatrixHTML(step.state)}
                      <p class="step-note">Biner: <code>${step.bits}</code> &nbsp;|&nbsp; Hex: <code>${step.hex}</code></p>
                    </div>`;
          break;
      }
    });
    stepsContainer.innerHTML = html;
  }

  // -----------------------------------------------------------
  // Validasi & submit
  // -----------------------------------------------------------
  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove('hidden');
  }
  function clearError() {
    errorBox.textContent = '';
    errorBox.classList.add('hidden');
  }

  function getMode() {
    return Array.from(modeRadios).find(r => r.checked).value;
  }

  function updateInputLabel() {
    inputLabel.textContent = getMode() === 'encrypt'
      ? 'Plaintext (16 bit biner)'
      : 'Ciphertext (16 bit biner)';
  }
  modeRadios.forEach(r => r.addEventListener('change', updateInputLabel));
  updateInputLabel();

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    clearError();

    const inputVal = inputField.value.trim();
    const keyVal = keyField.value.trim();
    const mode = getMode();

    if (!S.isValidBits16(inputVal)) {
      showError('Input plaintext/ciphertext harus berupa 16 digit biner (hanya 0 dan 1).');
      return;
    }
    if (!S.isValidBits16(keyVal)) {
      showError('Kunci harus berupa 16 digit biner (hanya 0 dan 1).');
      return;
    }

    const out = mode === 'encrypt' ? S.encrypt(inputVal, keyVal) : S.decrypt(inputVal, keyVal);

    outputBin.textContent = out.result;
    outputHex.textContent = out.resultHex;
    outputCaption.textContent = mode === 'encrypt' ? 'Ciphertext' : 'Plaintext';
    outputSection.classList.remove('hidden');

    renderSteps(out.steps);
    stepsContainer.classList.remove('hidden');
    stepsToggle.textContent = 'Sembunyikan Langkah Perhitungan ▲';
    stepsToggle.dataset.open = 'true';

    outputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  resetBtn.addEventListener('click', () => {
    form.reset();
    clearError();
    updateInputLabel();
    outputSection.classList.add('hidden');
    stepsContainer.classList.add('hidden');
    stepsContainer.innerHTML = '';
    stepsToggle.textContent = 'Tampilkan Langkah Perhitungan ▼';
    stepsToggle.dataset.open = 'false';
  });

  stepsToggle.addEventListener('click', () => {
    const open = stepsToggle.dataset.open === 'true';
    if (open) {
      stepsContainer.classList.add('hidden');
      stepsToggle.textContent = 'Tampilkan Langkah Perhitungan ▼';
      stepsToggle.dataset.open = 'false';
    } else {
      stepsContainer.classList.remove('hidden');
      stepsToggle.textContent = 'Sembunyikan Langkah Perhitungan ▲';
      stepsToggle.dataset.open = 'true';
    }
  });

  // Input mask: hanya izinkan 0/1, maksimal 16 karakter
  [inputField, keyField].forEach((field) => {
    field.addEventListener('input', () => {
      field.value = field.value.replace(/[^01]/g, '').slice(0, 16);
    });
  });

  renderRefTables();
});
