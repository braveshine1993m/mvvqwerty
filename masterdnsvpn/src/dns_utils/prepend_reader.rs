// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use tokio::io::AsyncReadExt;

/// Wraps a Tokio AsyncRead to prepend initial data (like SOCKS5 target)
/// before reading from the actual socket.
pub struct PrependReader<R: AsyncReadExt + Unpin> {
    reader: R,
    initial_data: Vec<u8>,
    initial_offset: usize,
}

impl<R: AsyncReadExt + Unpin> PrependReader<R> {
    pub fn new(reader: R, initial_data: Vec<u8>) -> Self {
        PrependReader {
            reader,
            initial_data,
            initial_offset: 0,
        }
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.initial_data.len() - self.initial_offset;
        if remaining > 0 {
            let to_copy = remaining.min(buf.len());
            buf[..to_copy].copy_from_slice(
                &self.initial_data[self.initial_offset..self.initial_offset + to_copy],
            );
            self.initial_offset += to_copy;
            return Ok(to_copy);
        }
        self.reader.read(buf).await
    }

    /// Get a mutable reference to the underlying reader.
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consume and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }
}
