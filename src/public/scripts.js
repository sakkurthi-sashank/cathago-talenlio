/* eslint-disable no-alert */
const sidebar = document.getElementById('sidebar')
const userProfile = document.getElementById('userProfile')
const logoutCard = document.getElementById('logoutCard')

document.addEventListener('click', (e) => {
  if (window.innerWidth <= 768 && e.target.closest('#menuToggle')) {
    sidebar.classList.toggle('active')
  }
})

userProfile.addEventListener('click', (e) => {
  e.stopPropagation()
  logoutCard.classList.toggle('active')
})

document.addEventListener('click', (e) => {
  if (!userProfile.contains(e.target)) {
    logoutCard.classList.remove('active')
  }
})

const dropzone = document.getElementById('dropzone')
const fileInput = document.getElementById('fileInput')
const fileSelect = document.getElementById('fileSelect')
const uploadBtn = document.getElementById('uploadBtn')
const scanBtn = document.createElement('button') // Create Scan button dynamically

let selectedFile = null
let uploadedFileId = null // Store file ID after upload

// Dropzone Click -> Opens File Selector
dropzone.addEventListener('click', () => fileInput.click())

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault()
  dropzone.classList.add('dragover')
})

dropzone.addEventListener('dragleave', () => {
  dropzone.classList.remove('dragover')
})

dropzone.addEventListener('drop', (e) => {
  e.preventDefault()
  dropzone.classList.remove('dragover')
  selectedFile = e.dataTransfer.files[0]
})

fileInput.addEventListener('change', (e) => {
  selectedFile = e.target.files[0]
})

fileSelect.addEventListener('change', (e) => {
  selectedFile = e.target.files[0]
})

uploadBtn.addEventListener('click', async () => {
  if (!selectedFile) {
    alert('Please select a file first!')
    return
  }

  const formData = new FormData()
  formData.append('file', selectedFile)

  try {
    const response = await fetch('/upload', {
      method: 'POST',
      body: formData,
    })

    const data = await response.json()

    if (response.ok) {
      uploadedFileId = data.fileId
      alert('✅ File uploaded successfully!')

      scanBtn.id = 'scanBtn'
      scanBtn.textContent = '🔍 Scan for Similar Documents'
      scanBtn.classList.add('scan-btn')
      document.querySelector('.upload-container').appendChild(scanBtn)
      scanBtn.style.display = 'block'
    }
    else {
      alert(data.error || '❌ Failed to upload file.')
    }
  }
  catch (error) {
    console.warn(error)
    alert('⚠️ Error uploading file.')
  }
})

scanBtn.addEventListener('click', async () => {
  if (!uploadedFileId)
    return

  scanBtn.textContent = 'Scanning...'
  scanBtn.classList.add('loading')
  scanBtn.disabled = true

  try {
    const response = await fetch(`/compare/${uploadedFileId}`, {
      method: 'POST',
    })

    if (response.ok) {
      alert('✅ Scan Completed!')
      window.location.href = `/scans/${uploadedFileId}`
    }
    else {
      alert('❌ Failed to scan document.')
    }
  }
  catch (error) {
    console.error(error)
    alert('⚠️ Error scanning document.')
  }
  finally {
    scanBtn.textContent = '🔍 Scan for Similar Documents'
    scanBtn.classList.remove('loading')
    scanBtn.disabled = false
  }
})

scanBtn.addEventListener('click', async () => {
  if (!uploadedFileId)
    return

  try {
    const response = await fetch(`/compare/${uploadedFileId}`, { method: 'POST' })
    if (response.ok) {
      alert('Scan completed! Redirecting...')
      window.location.href = `/scans/${uploadedFileId}`
    }
    else {
      alert('Failed to scan documents.')
    }
  }
  catch (error) {
    console.error(error)
    alert('Error scanning documents.')
  }
})
