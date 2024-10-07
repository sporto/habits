import lustre/effect.{type Effect}

pub type Return(model, msg) =
  #(model, Effect(msg))

pub fn then(
  current: Return(model, msg),
  next: fn(model) -> Return(model, msg),
) -> Return(model, msg) {
  let #(model, fx) = current
  let #(new_model, new_fx) = next(model)
  #(new_model, effect.batch([fx, new_fx]))
}
