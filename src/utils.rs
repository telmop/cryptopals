use std::collections::HashSet;

pub fn count_unique_blocks(bytes: &[u8], block_size: usize) -> usize {
    assert!(block_size > 0);
    let mut unique_blocks = HashSet::new();
    for i in 0..(bytes.len() / block_size) {
        let block = &bytes[i * block_size..(i + 1) * block_size];
        unique_blocks.insert(block);
    }
    unique_blocks.len()
}

pub fn sleep(time: u32) {
    let wait_time = std::time::Duration::from_millis(time as u64);
    std::thread::sleep(wait_time);
}
