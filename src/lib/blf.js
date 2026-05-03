import bindings from 'bindings'

const isValid = bindings('blf_v2').validateSalt('$222333')
console.log(isValid)