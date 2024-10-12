import lustre/attribute.{class} as attr
import lustre/element/html.{div, text}

pub fn input(attrs) {
  html.input([class("h-10 p-2 rounded border"), ..attrs])
}

pub fn button_input(attrs) {
  html.input([
    class("cursor-pointer border px-2 py-2 rounded h-10 bg-sky-600 text-white"),
    ..attrs
  ])
}
