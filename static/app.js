/**
 * SecureCloud Frontend Interactive Logic
 * Handles File Drag & Drop, Multi-step Animation, Block Visualization,
 * Ciphertext Modal Inspection, and Bit-Perfect Reassembly.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileInput");
  const uploadBtn = document.getElementById("uploadBtn");
  const selectedFileBadge = document.getElementById("selectedFileBadge");
  const selectedFileName = document.getElementById("selectedFileName");
  const selectedFileSize = document.getElementById("selectedFileSize");
  const chunkSizeSelector = document.getElementById("chunkSizeSelector");
  const pipelineProgress = document.getElementById("pipelineProgress");
  const progressBarFill = document.getElementById("progressBarFill");
  
  // Progress Steps
  const stepHash = document.getElementById("stepHash");
  const stepSegment = document.getElementById("stepSegment");
  const stepEncrypt = document.getElementById("stepEncrypt");
  const stepCloud = document.getElementById("stepCloud");

  // Shards Canvas
  const segmentationPreview = document.getElementById("segmentationPreview");
  const shardsGrid = document.getElementById("shardsGrid");
  const shardsCountBadge = document.getElementById("shardsCountBadge");

  // Reassembly Fields
  const vaultSelect = document.getElementById("vaultSelect");
  const targetFileId = document.getElementById("targetFileId");
  const targetBlocks = document.getElementById("targetBlocks");
  const targetHash = document.getElementById("targetHash");
  const reassembleBtn = document.getElementById("reassembleBtn");

  // Audit Results
  const auditCard = document.getElementById("auditCard");
  const auditExpectedHash = document.getElementById("auditExpectedHash");
  const auditReconstructedHash = document.getElementById("auditReconstructedHash");
  const auditSize = document.getElementById("auditSize");
  const auditStatusText = document.getElementById("auditStatusText");
  const auditIcon = document.getElementById("auditIcon");
  const auditBadge = document.getElementById("auditBadge");
  const downloadRestoredFileBtn = document.getElementById("downloadRestoredFileBtn");

  // Ciphertext Modal
  const cipherModal = document.getElementById("cipherModal");
  const modalCloseBtn = document.getElementById("modalCloseBtn");
  const modalBlockTitle = document.getElementById("modalBlockTitle");
  const modalCipherPreview = document.getElementById("modalCipherPreview");
  const modalBlockMeta = document.getElementById("modalBlockMeta");

  // State
  let currentFile = null;
  let selectedChunkSize = 524288; // 512 KB
  let uploadedSessions = [];

  // =========================================================================
  // 1. Initialize System Status
  // =========================================================================
  async function fetchStatus() {
    try {
      const res = await fetch("/api/status");
      const data = await res.json();
      document.getElementById("backendLabel").textContent = data.backend_label;
      document.getElementById("backendBucket").textContent = `Bucket: ${data.bucket_name} (${data.region})`;
    } catch (e) {
      document.getElementById("backendLabel").textContent = "Local Storage (Offline)";
      document.getElementById("backendBucket").textContent = "Bucket: sppu-cloud-secure-storage";
    }
  }
  fetchStatus();

  // =========================================================================
  // 2. Drag & Drop Handling
  // =========================================================================
  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function handleFileSelected(file) {
    currentFile = file;
    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = formatBytes(file.size);
    selectedFileBadge.style.display = "inline-flex";
    uploadBtn.removeAttribute("disabled");
  }

  // Chunk Size Selector Buttons
  chunkSizeSelector.querySelectorAll(".pill-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      chunkSizeSelector.querySelectorAll(".pill-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      selectedChunkSize = parseInt(btn.getAttribute("data-bytes"), 10);
    });
  });

  // =========================================================================
  // 3. Upload & Segmentation Workflow
  // =========================================================================
  uploadBtn.addEventListener("click", async () => {
    if (!currentFile) return;

    uploadBtn.setAttribute("disabled", "true");
    uploadBtn.innerHTML = `<span class="btn-icon">⏳</span> Encrypting & Segmenting...`;

    // Show Progress Bar
    pipelineProgress.style.display = "flex";
    progressBarFill.style.width = "15%";
    resetSteps();
    stepHash.classList.add("active");

    const formData = new FormData();
    formData.append("file", currentFile);
    formData.append("chunk_size", selectedChunkSize);

    try {
      // Animated step feedback
      setTimeout(() => {
        progressBarFill.style.width = "35%";
        stepHash.classList.remove("active");
        stepHash.classList.add("done");
        stepSegment.classList.add("active");
      }, 300);

      setTimeout(() => {
        progressBarFill.style.width = "65%";
        stepSegment.classList.remove("active");
        stepSegment.classList.add("done");
        stepEncrypt.classList.add("active");
      }, 700);

      const response = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`);
      }

      const resJson = await response.json();
      const data = resJson.data;

      // Finish progress bar
      progressBarFill.style.width = "100%";
      stepEncrypt.classList.remove("active");
      stepEncrypt.classList.add("done");
      stepCloud.classList.add("done");

      // Render Visual Shards Grid
      renderShardsGrid(data);

      // Auto-populate Right Panel for immediate test
      targetFileId.value = data.file_id;
      targetBlocks.value = data.total_blocks;
      targetHash.value = data.original_sha256;

      // Update Session Dropdown
      uploadedSessions.unshift(data);
      updateVaultSelect();

    } catch (err) {
      alert("Error during encryption/upload: " + err.message);
    } finally {
      uploadBtn.removeAttribute("disabled");
      uploadBtn.innerHTML = `<span class="btn-icon">⚡</span> Encrypt & Upload to Supabase`;
    }
  });

  function resetSteps() {
    [stepHash, stepSegment, stepEncrypt, stepCloud].forEach((s) => {
      s.classList.remove("active", "done");
    });
  }

  function renderShardsGrid(data) {
    segmentationPreview.style.display = "block";
    shardsCountBadge.textContent = `${data.total_blocks} Blocks (${formatBytes(data.chunk_size)} each)`;
    shardsGrid.innerHTML = "";

    data.blocks.forEach((block) => {
      const card = document.createElement("div");
      card.className = "shard-card";
      card.innerHTML = `
        <div class="shard-num">Block #${block.index}</div>
        <div class="shard-size">Plain: ${formatBytes(block.plaintext_size)}</div>
        <div class="shard-size">Encrypted: ${formatBytes(block.encrypted_size)}</div>
        <span class="shard-badge">AES-256 ✓</span>
      `;

      // Click to inspect raw ciphertext
      card.addEventListener("click", () => openCipherModal(block, data));
      shardsGrid.appendChild(card);
    });
  }

  function openCipherModal(block, fileData) {
    modalBlockTitle.textContent = `Ciphertext Inspector: ${block.filename}`;
    modalCipherPreview.value = block.cipher_preview + "\n\n[HMAC-SHA256 Authenticated Tag Appended]";
    modalBlockMeta.innerHTML = `
      <span><strong>File ID:</strong> ${fileData.file_id}</span>
      <span><strong>Cloud S3 Key:</strong> ${block.remote_key}</span>
      <span><strong>Plaintext Size:</strong> ${block.plaintext_size.toLocaleString()} bytes</span>
      <span><strong>Ciphertext Size:</strong> ${block.encrypted_size.toLocaleString()} bytes</span>
      <span><strong>Cryptographic Cipher:</strong> AES-128-CBC + HMAC-SHA256 (Fernet Standard)</span>
    `;
    cipherModal.style.display = "flex";
  }

  modalCloseBtn.addEventListener("click", () => {
    cipherModal.style.display = "none";
  });

  window.addEventListener("click", (e) => {
    if (e.target === cipherModal) {
      cipherModal.style.display = "none";
    }
  });

  function updateVaultSelect() {
    vaultSelect.innerHTML = `<option value="">-- Choose recently uploaded file --</option>`;
    uploadedSessions.forEach((item, index) => {
      const opt = document.createElement("option");
      opt.value = index;
      opt.textContent = `${item.filename} (${item.file_id}) - ${item.total_blocks} blocks`;
      vaultSelect.appendChild(opt);
    });
  }

  vaultSelect.addEventListener("change", (e) => {
    const idx = e.target.value;
    if (idx !== "") {
      const item = uploadedSessions[idx];
      targetFileId.value = item.file_id;
      targetBlocks.value = item.total_blocks;
      targetHash.value = item.original_sha256;
    }
  });

  // =========================================================================
  // 4. Download & Reassembly Workflow
  // =========================================================================
  reassembleBtn.addEventListener("click", async () => {
    const fileId = targetFileId.value.trim();
    const blocksCount = parseInt(targetBlocks.value, 10);
    const expectedHash = targetHash.value.trim();

    if (!fileId || !blocksCount || !expectedHash) {
      alert("Please fill in File ID, Total Blocks, and Expected SHA-256 Hash.");
      return;
    }

    reassembleBtn.setAttribute("disabled", "true");
    reassembleBtn.innerHTML = `<span class="btn-icon">⏳</span> Fetching & Decrypting from Supabase...`;
    auditCard.style.display = "none";

    // Determine filename if available
    let originalFilename = "restored_file";
    const matched = uploadedSessions.find((s) => s.file_id === fileId);
    if (matched) {
      originalFilename = matched.filename;
    }

    try {
      const response = await fetch("/api/download", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_id: fileId,
          total_blocks: blocksCount,
          expected_hash: expectedHash,
          original_filename: originalFilename,
        }),
      });

      if (!response.ok) {
        const errJson = await response.json();
        throw new Error(errJson.detail || "Reassembly failed");
      }

      const result = await response.json();

      // Display Audit Results
      auditCard.style.display = "flex";
      auditExpectedHash.textContent = result.expected_hash;
      auditReconstructedHash.textContent = result.reconstructed_hash;
      auditSize.textContent = `${result.reconstructed_size.toLocaleString()} bytes (${formatBytes(result.reconstructed_size)})`;

      if (result.is_bit_perfect) {
        auditStatusText.textContent = "100% BIT-PERFECT MATCH (PASS)";
        auditStatusText.style.color = "#34d399";
        auditIcon.textContent = "✓";
        auditIcon.style.background = "#10b981";
      } else {
        auditStatusText.textContent = "INTEGRITY MISMATCH (FAIL)";
        auditStatusText.style.color = "#ef4444";
        auditIcon.textContent = "✕";
        auditIcon.style.background = "#ef4444";
      }

      // Configure direct download link
      downloadRestoredFileBtn.href = result.download_url;
      downloadRestoredFileBtn.setAttribute("download", result.filename);

    } catch (err) {
      alert("Reassembly Error: " + err.message);
    } finally {
      reassembleBtn.removeAttribute("disabled");
      reassembleBtn.innerHTML = `<span class="btn-icon">🔓</span> Decrypt, Stitch & Verify Integrity`;
    }
  });

});
