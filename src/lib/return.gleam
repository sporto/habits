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

pub fn map_msg(
  current: Return(model, msg),
  mapper: fn(msg) -> msg2,
) -> Return(model, msg2) {
  let #(model, fx) = current
  #(model, effect.map(fx, mapper))
}
