use paste::paste;
#[macro_export]
macro_rules! generate_ic_model {
    ($i : ty, $guard_func : ident, $store : ident) => {
        // creating CREEATE function
        paste! {
            #[ic_cdk::update]
            fn [<create_ $i:lower>] (data : $i) -> Result<i32, String> {
                $guard_func();

                return $store.with(|store| {
                    let mut binding = store.borrow_mut();
                    if binding.contains_key(&data.id) {
                        return Result::Err("Entry Exists".to_string())
                    } else {
                        binding.insert(data.id.clone(), data);
                        return Result::Ok(200);
                    }
                });
            }

            #[ic_cdk::query]
            fn [<get_ $i:lower>] (data_id : String) -> Result<$i, String> {
                $guard_func();
                return $store.with(|store| {
                    let binding = store.borrow();
                    let rslt = binding.get(&data_id);
                    match rslt {
                        Some(data) => {
                            return Result::Ok::<$i, String>(data.clone());
                        },
                        None => {
                            return Result::Err("Not Found".to_string())
                        }
                    }
                });
            }

            #[ic_cdk::update]
            fn [<update_ $i:lower>] (data_id : String, data : $i) -> Result<i32, &'static str> {
                $guard_func();
                return $store.with(|store| {
                    let mut binding = store.borrow_mut();
                    if binding.contains_key(&data_id) {
                        binding.insert(data_id, data);
                        return Result::Ok(200)
                    } else { return Result::Err("Not Found") }
                })
            }

            #[ic_cdk::update]
            fn [<delete_ $i:lower>] (data_id : String) -> Result<i32, &'static str> {
                $guard_func();
                return $store.with(|store| {
                    let mut binding = store.borrow_mut();
                    if binding.contains_key(&data_id) {
                        binding.remove(&data_id);
                        return Result::Ok(200)
                    } else {
                        return Result::Err("Not Found")
                    }
                    
                })
            }

            #[ic_cdk::query]
            fn [<get_all_ $i:lower>] () -> Result<Vec<$i>, &'static str> {
                $guard_func();
                $store.with(|store| {
                    let data = store.borrow().values().cloned().collect();
                    return Result::Ok(data)
                })
            }

          
        }
    };
}