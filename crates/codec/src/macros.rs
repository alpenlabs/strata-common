//! Simple macros for basic codec impls.

/// Generates a `Codec` impl for a wrapper type.
#[macro_export]
macro_rules! impl_wrapper_codec {
    ($this:ty => $target:ty) => {
        impl $crate::Codec for $this {
            fn decode(dec: &mut impl $crate::Decoder) -> Result<Self, $crate::CodecError> {
                <$target as $crate::Codec>::decode(dec).map(Self)
            }

            fn encode(&self, enc: &mut impl $crate::Encoder) -> Result<(), $crate::CodecError> {
                self.0.encode(enc)
            }
        }
    };
}

/// Generates a struct with `Codec` impls, assuming each of its fields are .
// TODO convert this to a proc macro (but not a derive macro so we can add attrs to fields)
#[macro_export]
macro_rules! impl_type_flat_struct {
    {
        $( #[ $sattr:meta ] )*
        $v:vis struct $name:ident {
            $(
                $( #[ $fattr:meta ] )*
                $fname:ident : $fty:ty,
            )*
        }
    } => {
        $( #[ $sattr ] )*
        $v struct $name {
            $(
                $( #[ $fattr ] )*
                $fname : $fty,
            )*
        }

        impl $name {
            $v fn new($( $fname : $fty ),*) -> Self {
                Self { $( $fname ),* }
            }

            $(
                $v fn $fname(&self) -> &$fty {
                    &self.$fname
                }
            )*
        }

        impl $crate::Codec for $name {
            fn decode(dec: &mut impl $crate::Decoder) -> Result<Self, $crate::CodecError> {
                $(
                    let $fname = <$fty as $crate::Codec>::decode(dec)?;
                )*
                Ok(Self::new($($fname),*))
            }

            fn encode(&self, enc: &mut impl $crate::Encoder) -> Result<(), $crate::CodecError> {
                $(<$fty as $crate::Codec>::encode(&self.$fname, enc)?;)*
                Ok(())
            }
        }
    }
}
