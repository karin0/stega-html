function b64decode(s) {
  const t = s.length % 4
  if (t) s += '==='.slice(0, 4 - t)
  return Uint8Array.from(atob(s), c => c.charCodeAt(0))
}

async function decrypt(b64_msg, b64_key) {
  const key = await crypto.subtle.importKey(
    'raw',
    b64decode(b64_key),
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  )
  const buf = b64decode(b64_msg)
  const plain_text = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf.slice(0, 16) },
    key,
    buf.slice(16),
  )
  return new TextDecoder().decode(plain_text)
}

(() => {
  const cipher_text = document.getElementById('cipher').innerText
  let key = localStorage.getItem('key')
  let is_new = !key
  if (is_new) {
    key = prompt()
    if (!key) return
  }
  decrypt(cipher_text, key)
    .then(text => {
      document.write(text)
      if (is_new) localStorage.setItem('key', key)
    })
    .catch(e => {
      console.error(e)
      document.write(String(e))
    })
})()
