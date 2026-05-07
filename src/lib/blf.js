import bindings from 'bindings'
import crypto from 'crypto'

const blf = bindings('blf_v2')
console.log(blf)

const salt_buf = crypto.randomBytes(16)
const salt = blf.generateSaltSync('a', 10, salt_buf)
console.log(salt)
const isValid = blf.validateSaltSync(salt)
console.log(isValid)
const hash = blf.hashSync(salt, "H")
console.log(hash)

blf.hashAsync(salt, "H").then(res => console.log(res)).catch(console.error)