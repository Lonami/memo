#![macro_use]
use std::io;

pub trait SerDes: Sized {
    fn load<R: io::Read>(reader: &mut R) -> io::Result<Self>;
    fn save<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;
}

#[macro_export]
macro_rules! define_serdes {
    ($(#[$attrs:meta])* $outervis:vis struct $name:ident {
        $($vis:vis $field:ident : $ty:ty,)*
    }) => {
        $(#[$attrs])*
        $outervis struct $name {
            $($vis $field: $ty,)*
        }

        impl crate::scanner::serdes::SerDes for $name {
            fn load<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
                Ok(Self {
                    $($field: <$ty as crate::scanner::serdes::SerDes>::load(reader)?,)*
                })
            }

            fn save<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                $(<$ty as crate::scanner::serdes::SerDes>::save(&self.$field, writer)?;)*
                Ok(())
            }
        }
    };
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

impl<T: SerDes> SerDes for Vec<T> {
    fn load<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let len = <usize as SerDes>::load(reader)?;
        let mut res = Vec::with_capacity(len);
        for _ in 0..len {
            res.push(<T as SerDes>::load(reader)?);
        }
        Ok(res)
    }

    fn save<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        <usize as SerDes>::save(&self.len(), writer)?;
        for item in self {
            <T as SerDes>::save(&item, writer)?;
        }
        Ok(())
    }
}
