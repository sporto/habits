import gleroglero/solid
import lustre/attribute.{class} as attr
import lustre/element/html.{div, span, text}

fn icon_wrapper(icon) {
  div([class("w-5 h-5")], [icon])
}

pub fn icon_clear() {
  icon_wrapper(solid.x_mark())
}

pub fn input(attrs) {
  html.input([class("h-10 p-2 rounded border"), ..attrs])
}

pub fn button_input(attrs) {
  html.input([
    class("cursor-pointer border px-2 py-2 rounded h-10 bg-sky-600 text-white"),
    ..attrs
  ])
}

pub fn button(attrs, children) {
  html.button([class("t-button"), ..attrs], children)
}
