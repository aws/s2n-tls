// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::{
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};
use std::{sync::Arc, task::Wake};

/// Checks that if a function returns [`Poll::Pending`], then the function called [`Waker::clone`],
/// [`Waker::wake`], or [`Waker::wake_by_ref`] on the [`Context`]'s [`Waker`].
pub struct Contract {
    state: Arc<State>,
    waker: Waker,
}

struct State {
    inner: Waker,
    wake_called: AtomicBool,
}

impl Wake for State {
    #[inline]
    fn wake(self: Arc<Self>) {
        Wake::wake_by_ref(&self)
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_called.store(true, Ordering::Release);
        self.inner.wake_by_ref();
    }
}

impl Contract {
    /// Wraps a [`Context`] in the contract checker
    #[inline]
    pub fn new(cx: &mut Context) -> Self {
        let state = State {
            inner: cx.waker().clone(),
            wake_called: AtomicBool::new(false),
        };
        let state = Arc::new(state);
        let waker = Waker::from(state.clone());
        Self { state, waker }
    }

    /// Returns a new [`Context`] to be checked
    #[inline]
    pub fn context(&self) -> Context {
        Context::from_waker(&self.waker)
    }

    /// Checks the state of the waker based on the provided `outcome`
    #[inline]
    #[track_caller]
    pub fn check_outcome<T>(self, outcome: &Poll<T>) {
        if outcome.is_ready() {
            return;
        }

        let strong_count = Arc::strong_count(&self.state);
        let is_cloned = strong_count > 2; // 1 for `state`, one for our owned `waker`
        let wake_called = self.state.wake_called.load(Ordering::Acquire);

        let is_ok = is_cloned || wake_called;

        assert!(
            is_ok,
            "strong_count = {strong_count}; is_cloned = {is_cloned}; wake_called = {wake_called}"
        );
    }
}

/// Checks that if a function returns [`Poll::Pending`], then the function called [`Waker::clone`],
/// [`Waker::wake`], or [`Waker::wake_by_ref`] on the [`Context`]'s [`Waker`].
#[inline(always)]
#[track_caller]
pub fn assert_contract<F: FnOnce(&mut Context) -> Poll<R>, R>(cx: &mut Context, f: F) -> Poll<R> {
    let contract = Contract::new(cx);
    let mut cx = contract.context();
    let outcome = f(&mut cx);
    contract.check_outcome(&outcome);
    outcome
}

/// Checks that if a function returns [`Poll::Pending`], then the function called [`Waker::clone`],
/// [`Waker::wake`], or [`Waker::wake_by_ref`] on the [`Context`]'s [`Waker`].
///
/// This is only enabled with `debug_assertions`.
#[inline(always)]
#[track_caller]
pub fn debug_assert_contract<F: FnOnce(&mut Context) -> Poll<R>, R>(
    cx: &mut Context,
    f: F,
) -> Poll<R> {
    #[cfg(debug_assertions)]
    return assert_contract(cx, f);

    #[cfg(not(debug_assertions))]
    return f(cx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    pub fn noop() -> Waker {
        use core::{
            ptr,
            task::{RawWaker, RawWakerVTable},
        };

        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            // Cloning just returns a new no-op raw waker
            |_| RAW,
            // `wake` does nothing
            |_| {},
            // `wake_by_ref` does nothing
            |_| {},
            // Dropping does nothing as we don't allocate anything
            |_| {},
        );
        const RAW: RawWaker = RawWaker::new(ptr::null(), &VTABLE);

        unsafe { Waker::from_raw(RAW) }
    }

    #[test]
    fn correct_test() {
        let waker = noop();
        let mut cx = Context::from_waker(&waker);

        // the contract isn't violated when returning Ready
        let _ = assert_contract(&mut cx, |_cx| Poll::Ready(()));

        // the contract isn't violated if the waker is immediately woken
        let _ = assert_contract(&mut cx, |cx| {
            cx.waker().wake_by_ref();
            Poll::<()>::Pending
        });

        // the contract isn't violated if the waker is cloned then immediately woken
        let _ = assert_contract(&mut cx, |cx| {
            let waker = cx.waker().clone();
            waker.wake();
            Poll::<()>::Pending
        });

        // the contract isn't violated if the waker is cloned and stored for later
        let mut stored = None;
        let _ = assert_contract(&mut cx, |cx| {
            stored = Some(cx.waker().clone());
            Poll::<()>::Pending
        });
    }

    #[test]
    #[should_panic]
    fn incorrect_test() {
        let waker = noop();
        let mut cx = Context::from_waker(&waker);

        // the contract is violated if we return Pending without doing anything
        let _ = assert_contract(&mut cx, |_cx| Poll::<()>::Pending);
    }
}
