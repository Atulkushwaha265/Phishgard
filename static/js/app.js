document.addEventListener('DOMContentLoaded', () => {
  const message = document.querySelector('.flash')
  if (message) {
    setTimeout(() => message.style.opacity = '0.6', 2000)
  }

  const themeButton = document.getElementById('theme-toggle')
  if (themeButton) {
    themeButton.addEventListener('click', () => {
      document.body.classList.toggle('dark-mode')
      const label = document.body.classList.contains('dark-mode') ? 'Light Mode' : 'Dark Mode'
      themeButton.textContent = label
    })
  }
})
