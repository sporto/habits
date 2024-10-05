import gleam/dynamic
import gleam/int
import gleam/json
import gleam/list
import lustre
import lustre/attribute as attr
import lustre/effect
import lustre/element
import lustre/element/html.{div, text}
import lustre/event
import lustre_http

pub type Flags {
  Flags(api_url: String)
}

pub type Model {
  Model(
    cats: List(String),
    count: Int,
    email: String,
    flags: Flags,
    password: String,
  )
}

fn new_model() -> Model {
  Model(
    cats: [],
    count: 0,
    email: "",
    flags: Flags(api_url: "https://123.supabase.co"),
    password: "",
  )
}

fn init(_flags) -> #(Model, effect.Effect(Msg)) {
  #(new_model(), effect.none())
}

pub type Msg {
  UserIncrementedCount
  UserDecrementedCount
  ApiReturnedCat(Result(String, lustre_http.HttpError))
  ApiReturnedLoginResponse(Result(String, lustre_http.HttpError))
  ClickedLogin
  ChangedEmail(String)
  ChangedPassword(String)
}

pub fn main() {
  let app = lustre.application(init, update, view)
  let assert Ok(_) = lustre.start(app, "#app", Nil)

  Nil
}

pub fn update(model: Model, msg: Msg) -> #(Model, effect.Effect(Msg)) {
  case msg {
    UserIncrementedCount -> #(Model(..model, count: model.count + 1), get_cat())
    UserDecrementedCount -> #(
      Model(..model, count: model.count - 1),
      effect.none(),
    )
    ApiReturnedCat(Ok(cat)) -> #(
      Model(..model, cats: [cat, ..model.cats]),
      effect.none(),
    )
    ApiReturnedCat(Error(_)) -> #(model, effect.none())
    ChangedEmail(email) -> #(Model(..model, email: email), effect.none())
    ChangedPassword(password) -> #(
      Model(..model, password: password),
      effect.none(),
    )
    ClickedLogin -> #(model, effect.none())
  }
}

fn login(model: Model) -> effect.Effect(Msg) {
  let decoder = dynamic.field("_id", dynamic.string)
  let expect = lustre_http.expect_json(decoder, ApiReturnedLoginResponse)

  let payload =
    json.object([
      #("email", json.string(model.email)),
      #("password", json.string(model.password)),
    ])

  lustre_http.post(model.flags.api_url <> "/auth/v1/login", payload, expect)
}

fn get_cat() -> effect.Effect(Msg) {
  let decoder = dynamic.field("_id", dynamic.string)
  let expect = lustre_http.expect_json(decoder, ApiReturnedCat)

  lustre_http.get("https://cataas.com/cat?json=true", expect)
}

pub fn view(model: Model) -> element.Element(Msg) {
  let count = int.to_string(model.count)

  html.div([], [
    view_login(model),
    html.button([event.on_click(UserIncrementedCount)], [element.text("+")]),
    element.text(count),
    html.button([event.on_click(UserDecrementedCount)], [element.text("-")]),
    html.div(
      [],
      list.map(model.cats, fn(cat) {
        html.img([attr.src("https://cataas.com/cat/" <> cat)])
      }),
    ),
  ])
}

fn view_login(model: Model) {
  html.form([event.on_submit(ClickedLogin)], [
    div([], [
      html.label([], [text("Email")]),
      html.input([attr.type_("text"), attr.value(model.email)]),
    ]),
    div([], [
      html.label([], [text("Passsword")]),
      html.input([attr.type_("password"), attr.value(model.password)]),
    ]),
    div([], [html.input([attr.type_("submit"), attr.value("Login")])]),
  ])
}
