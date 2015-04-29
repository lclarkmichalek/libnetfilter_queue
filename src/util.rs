// `as_mut` and `as_ref` are not stable, so are reproduced here to avoid the compiler error.
// Copypasta from <https://github.com/rust-lang/rust/blob/f46c4e158d395cf6e186bf6afdf1705c12071cbe/src/libcore/ptr.rs#L370-376>

#[inline]
pub unsafe fn as_mut<'a, T: ?Sized>(ptr: &*mut T) -> Option<&'a mut T> where T: Sized {
    if ptr.is_null() {
        None
    } else {
        Some(&mut **ptr)
    }
}

#[inline]
pub unsafe fn as_ref<'a, T: ?Sized>(ptr: &*const T) -> Option<&'a T> where T: Sized {
    if ptr.is_null() {
        None
    } else {
        Some(&**ptr)
    }
}
