let blocksCache = [];
const filterState = { query: '', category: 'All' };

function extractCategory(data) {
  if (!data) return null;
  const match = data.match(/Category:\s*([^\n]+)/i);
  return match ? match[1].trim() : null;
}

function applyFilters(blocks) {
  const query = filterState.query.toLowerCase();
  return blocks.filter(b => {
    const text = [
      b.data,
      b.author,
      b.verified_by,
      b.hash,
      b.previous_hash
    ].filter(Boolean).join(' ').toLowerCase();

    if (query && !text.includes(query)) return false;

    if (filterState.category !== 'All') {
      const cat = extractCategory(b.data);
      if (cat) {
        return cat.toLowerCase() === filterState.category.toLowerCase();
      }
      return text.includes(filterState.category.toLowerCase());
    }

    return true;
  });
}

function renderBlocks(blocks) {
  const container = document.getElementById('chain');
  container.innerHTML = '';
  blocks.slice().reverse().forEach(b => {
    const el = document.createElement('div');
    el.className = 'card block-card';
    const authorBadge = b.author ? `<span class="badge bg-info ms-2">${b.author}</span>` : '';
    const sigBadge = b.signature ? `<span class="badge bg-success ms-2">Signed</span>` : '';
    const verifiedBadge = b.verified_by ? `<span class="badge bg-warning ms-2">Verified by ${b.verified_by}</span>` : '';
    const photoHtml = b.photo_base64 ? `<div class="mt-2"><img src="data:image/jpeg;base64,${b.photo_base64}" class="img-fluid" style="max-height:200px;border-radius:4px;" alt="Activity photo"/></div>` : '';
    const category = extractCategory(b.data);
    const categoryBadge = category ? `<span class="badge bg-secondary ms-2">${category}</span>` : '';
    el.innerHTML = `<div class="card-body">
      <div class="d-flex align-items-center mb-2 flex-wrap">
        <h6 class="card-title mb-0">Block #${b.index}</h6>
        ${authorBadge}
        ${sigBadge}
        ${verifiedBadge}
        ${categoryBadge}
      </div>
      <p class="card-subtitle text-muted">${b.timestamp}</p>
      <p class="card-text mt-2"><strong>Data:</strong> ${b.data}</p>
      ${photoHtml}
      <div class="mt-2">
        <p class="small mb-1"><strong>Previous Hash:</strong></p>
        <span class="hash">${b.previous_hash}</span>
      </div>
      <div class="mt-2">
        <p class="small mb-1"><strong>Hash:</strong></p>
        <span class="hash">${b.hash}</span>
      </div>
    </div>`;
    container.appendChild(el);
  });
}

async function fetchBlocks() {
  const res = await fetch('/api/blocks');
  const payload = await res.json();
  const blocks = Array.isArray(payload) ? payload : (payload.blocks || []);
  blocksCache = blocks;
  renderBlocks(applyFilters(blocksCache));
}

document.getElementById('mineForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = document.getElementById('dataInput').value;
  const photoFile = document.getElementById('photoInput').files[0];
  const verifiedBy = document.getElementById('verifiedByInput').value || null;
  
  const formData = new FormData();
  formData.append('data', data);
  if (verifiedBy) formData.append('verified_by', verifiedBy);
  if (photoFile) formData.append('photo', photoFile);
  
  const res = await fetch('/api/mine', {
    method: 'POST',
    body: formData
  });
  if (res.status === 401) {
    alert('You must be logged in to add blocks.');
    return;
  }
  document.getElementById('dataInput').value = '';
  document.getElementById('photoInput').value = '';
  document.getElementById('verifiedByInput').value = '';
  fetchBlocks();
});

document.getElementById('clearBtn').addEventListener('click', () => {
  document.getElementById('dataInput').value = '';
});

document.getElementById('searchInput').addEventListener('input', (e) => {
  filterState.query = e.target.value;
  renderBlocks(applyFilters(blocksCache));
});

document.getElementById('categoryFilter').addEventListener('change', (e) => {
  filterState.category = e.target.value;
  renderBlocks(applyFilters(blocksCache));
});

document.getElementById('clearFilters').addEventListener('click', () => {
  filterState.query = '';
  filterState.category = 'All';
  document.getElementById('searchInput').value = '';
  document.getElementById('categoryFilter').value = 'All';
  renderBlocks(applyFilters(blocksCache));
});

document.querySelectorAll('.template-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const type = btn.dataset.template;
    document.getElementById('dataInput').value = `Category: ${type}\nActivity: `;
    document.getElementById('dataInput').focus();
  });
});

fetchBlocks();
setInterval(fetchBlocks, 2000);

// Update QR for the latest block
async function updateBlockQr() {
  const res = await fetch('/api/blocks');
  const payload = await res.json();
  const blocks = Array.isArray(payload) ? payload : (payload.blocks || []);
  if (blocks.length) {
    const latest = blocks[blocks.length - 1];
    const text = encodeURIComponent(JSON.stringify(latest));
    document.getElementById('blockQr').src = '/qr?text=' + text;
  }
}

setInterval(updateBlockQr, 2000);
updateBlockQr();

// Auth handling
document.getElementById('showRegister').addEventListener('click', () => {
  window.location.href = '/signup';
});
document.getElementById('showLogin').addEventListener('click', () => {
  document.getElementById('loginForm').style.display = 'block';
  document.getElementById('registerForm').style.display = 'none';
});

document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('regUser').value;
  const password = document.getElementById('regPass').value;
  const res = await fetch('/api/register', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({username, password})
  });
  if (res.ok) {
    const j = await res.json();
    setUser(j.user);
  } else {
    const j = await res.json(); alert('Register error: '+(j.error||'unknown'));
  }
});

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('loginUser').value;
  const password = document.getElementById('loginPass').value;
  const res = await fetch('/api/login', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({username, password})
  });
  if (res.ok) {
    const j = await res.json(); setUser(j.user);
  } else { const j = await res.json(); alert('Login error: '+(j.error||'invalid')) }
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
  await fetch('/api/logout', {method:'POST'});
  setUser(null);
});

function setUser(u){
  if (u) {
    document.getElementById('currentUser').textContent = u;
    document.getElementById('loggedIn').style.display = 'block';
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('headerUser').textContent = `${u} ✓`;
    document.getElementById('mineForm').style.display = 'block';
  } else {
    document.getElementById('loggedIn').style.display = 'none';
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('headerUser').textContent = '';
    document.getElementById('mineForm').style.display = 'none';
  }
}

// Verification
document.getElementById('verifyBtn').addEventListener('click', async () => {
  document.getElementById('verifyBtn').disabled = true;
  document.getElementById('verifyBtn').innerHTML = '<i class="bi bi-hourglass-split"></i> Verifying...';
  
  const res = await fetch('/api/verify');
  const j = await res.json();
  const problems = j.problems || [];
  const box = document.getElementById('verifyResults');
  
  if (problems.length === 0) {
    box.innerHTML = '<div class="alert alert-success"><i class="bi bi-check-circle"></i> <strong>Chain integrity OK!</strong> All blocks are valid and cryptographically sound.</div>';
  } else {
    let html = '<div class="alert alert-warning"><strong><i class="bi bi-exclamation-triangle"></i> Issues found:</strong><ul class="mb-0 mt-2">';
    problems.forEach(p => {
      html += `<li><strong>Block ${p.index}:</strong> ${p.problem}</li>`;
    });
    html += '</ul></div>';
    box.innerHTML = html;
  }
  box.style.display = 'block';
  document.getElementById('verifyBtn').disabled = false;
  document.getElementById('verifyBtn').innerHTML = '<i class="bi bi-lightning-charge"></i> Verify Chain';
  updateVerifyBanner();
});

async function updateVerifyBanner() {
  try {
    const res = await fetch('/api/verify');
    const j = await res.json();
    const problems = j.problems || [];
    const banner = document.getElementById('verifyBanner');
    if (problems.length === 0) {
      banner.className = 'alert alert-success';
      banner.textContent = 'Integrity OK. All records are valid.';
    } else {
      banner.className = 'alert alert-warning';
      banner.textContent = `Integrity issues found: ${problems.length}. See Verification panel for details.`;
    }
    banner.classList.remove('d-none');
  } catch (err) {
    // ignore banner errors
  }
}

setInterval(updateVerifyBanner, 30000);
updateVerifyBanner();

// QR Scanner (uses html5-qrcode included on page)
let html5QrCode = null;
function showScanner(show) {
  document.getElementById('qrScannerContainer').style.display = show ? 'block' : 'none';
}

async function startScan() {
  try {
    showScanner(true);
    const qrRegionId = 'qrScanner';
    if (!window.Html5Qrcode) {
      alert('QR scanner library not loaded.');
      return;
    }
    html5QrCode = new Html5Qrcode(qrRegionId);
    const config = { fps: 10, qrbox: 250 };
    await html5QrCode.start({ facingMode: 'environment' }, config, (decodedText, decodedResult) => {
      // on success
      document.getElementById('dataInput').value = decodedText;
      stopScan();
    });
  } catch (err) {
    console.error('startScan error', err);
    alert('Unable to start camera for scanning: ' + err);
    showScanner(false);
  }
}

function stopScan() {
  if (html5QrCode) {
    html5QrCode.stop().then(() => {
      html5QrCode.clear();
      html5QrCode = null;
      showScanner(false);
    }).catch(err => {
      console.warn('stopScan error', err);
      showScanner(false);
    });
  } else {
    showScanner(false);
  }
}

document.getElementById('scanBtn').addEventListener('click', startScan);
document.getElementById('stopScanBtn').addEventListener('click', stopScan);

