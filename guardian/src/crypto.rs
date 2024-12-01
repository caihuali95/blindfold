use crate::*;
use crate::hmac::Mac;

pub fn check_hash(paddr: u64, size: u64, cipher: &Arc<HmacSha256>, _hash_vaddr: u64) {
	let mut hmac = Arc::unwrap_or_clone(cipher.clone());
	hmac.update(addr_to_slice::<u8>(paddr_to_gaddr(paddr), size).as_ref());
	hmac.finalize().into_bytes();
}
fn aes_enc(plaintext: &[u8], _ciphertext: &mut [u8; BLOCK_SIZE], _cipher: &Arc<Aes128>) {
	let mut array = [0u8; BLOCK_SIZE];
	array.copy_from_slice(&plaintext[0..BLOCK_SIZE]);
	//cipher.encrypt_block(&mut GenericArray::from(array));
	//ciphertext.copy_from_slice(&array);
}
fn aes_dec(ciphertext: &[u8], _plaintext: &mut [u8; BLOCK_SIZE], _cipher: &Arc<Aes128>) {
	let mut array = [0u8; BLOCK_SIZE];
	array.copy_from_slice(&ciphertext[0..BLOCK_SIZE]);
	//cipher.decrypt_block(&mut GenericArray::from(array));
	//plaintext.copy_from_slice(&array);
}
pub fn crypto_page(paddr: u64, aes_key: &Arc<Aes128>, is_encrypt: bool) {
	let mut tmp = [0u8; BLOCK_SIZE];
	let page = addr_to_slice::<u8>(paddr_to_gaddr(paddr), PAGE_SIZE);
	for i in (0..PAGE_SIZE as usize).step_by(BLOCK_SIZE) {
		if is_encrypt { aes_enc(&page[i..], &mut tmp, aes_key); }
		else { aes_dec(&page[i..], &mut tmp, aes_key); }
	}
}