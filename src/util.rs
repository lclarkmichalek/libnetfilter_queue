/// Returns `None` if the pointer is null, or else returns a mutable
/// reference to the value wrapped in `Some`.
///
/// # Safety
///
/// As with `as_ref`, this is unsafe because it cannot verify the validity
/// of the returned pointer.
///
/// *`as_mut` is not stable, so is reproduced here to avoid the compiler error.*
/// *Copypasta from <https://github.com/rust-lang/rust/blob/f46c4e158d395cf6e186bf6afdf1705c12071cbe/src/libcore/ptr.rs#L370-376>*
#[inline]
pub unsafe fn as_mut<'a, T: ?Sized>(pointer: &*mut T) -> Option<&'a mut T> where T: Sized {
    if pointer.is_null() {
        None
    } else {
        Some(&mut **pointer)
    }
}
