import gleroglero/outline
import gleroglero/solid
import lustre/attribute.{class} as attr
import lustre/element/html.{div, span, text}

fn icon_wrapper(attrs, icon) {
  div([class("w-5 h-5"), ..attrs], [icon])
}

pub fn icon_archive(attrs) {
  icon_wrapper(attrs, solid.archive_box_arrow_down())
}

pub fn icon_clear(attrs) {
  icon_wrapper(attrs, solid.x_mark())
}

pub fn icon_check(attrs) {
  icon_wrapper(attrs, solid.check())
}

pub fn icon_chevron_left(attrs) {
  icon_wrapper(attrs, solid.chevron_left())
}

pub fn icon_chevron_right(attrs) {
  icon_wrapper(attrs, solid.chevron_right())
}

pub fn icon_trash(attrs) {
  icon_wrapper(attrs, solid.trash())
}

pub fn icon_unarchive(attrs) {
  icon_wrapper(attrs, outline.archive_box_x_mark())
}

pub fn input(attrs) {
  html.input([class("h-12 p-2 rounded border"), ..attrs])
}

pub fn button_input(attrs) {
  html.input([
    class("cursor-pointer border px-4 py-2 rounded h-12 bg-sky-600 text-white"),
    ..attrs
  ])
}

pub fn button_link(attrs, children) {
  html.a(
    [
      class(
        "t-button px-3 border border-slate-400 rounded h-12 inline-flex items-center",
      ),
      ..attrs
    ],
    children,
  )
}

pub fn button(attrs, children) {
  button_only(
    [
      class(
        "px-3 border border-slate-400 rounded h-12 inline-flex items-center",
      ),
      ..attrs
    ],
    children,
  )
}

pub fn button_only(attrs, children) {
  html.button([class("t-button"), ..attrs], children)
}

pub fn modal(children) {
  html.div(
    [
      class(
        "t-modal-backdrop fixed top-0 bottom-0 left-0 right-0 bg-slate-900/60 px-4",
      ),
    ],
    [
      html.dialog(
        [
          class("t-modal bg-white rounded p-4"),
          attr.style([#("margin-top", "12rem")]),
          attr.open(True),
        ],
        children,
      ),
    ],
  )
}
