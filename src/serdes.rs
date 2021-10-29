use std::io;

pub trait SerDes: Sized {
    fn load<R: io::Read>(reader: &mut R) -> io::Result<Self>;
    fn save<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;
}

macro_rules! impl_serdes_ints {
    ($($ty:ty),*) => {
        $(impl SerDes for $ty {
            fn load<R: io::Read>(reader: &mut R) -> io::Result<Self> {
                let mut buf = [0u8; std::mem::size_of::<Self>()];
                reader
                    .read_exact(buf.as_mut())
                    .map(|_| Self::from_ne_bytes(buf))
            }
            fn save<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
                writer.write_all(&self.to_ne_bytes())
            }
        })*
    };
}

impl_serdes_ints!(i8, u8, i16, u16, i32, u32, i64, u64, isize, usize);

impl SerDes for bool {
    fn load<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(buf.as_mut()).map(|_| buf[0] != 0)
    }

    fn save<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[*self as u8])
    }
}
