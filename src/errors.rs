error_chain! {
    foreign_links {
        Io(::std::io::Error);
        //Mmap(::mmap::MapError);
        Nom(::nom::Err);
        Utf8(::std::str::Utf8Error);
    }

    errors {
        Null
        Incomplete
        IncorrectBlobType
    }
}

impl From<()> for Error {
    fn from(_x: ()) -> Error {
        ErrorKind::Null.into()
    }
}
