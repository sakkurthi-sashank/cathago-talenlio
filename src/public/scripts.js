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

let selectedFile = null

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

    if (response.ok) {
      alert('File uploaded successfully!')
    }
    else {
      alert('Failed to upload file.')
    }
  }
  catch (error) {
    console.warn(error)
    alert('Error uploading file.')
  }
})
