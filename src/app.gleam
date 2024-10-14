import app/buttons
import app/components
import app/icons
import birl
import gleam/dynamic
import gleam/http.{type Method, Get, Https, Post}
import gleam/http/request.{type Request}
import gleam/io
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result.{try}
import gleam/string
import gleam/uri.{type Uri}
import lib/return
import lustre
import lustre/attribute.{class, style} as attr
import lustre/effect
import lustre/element.{type Element}
import lustre/element/html.{div, text}
import lustre/event
import lustre_http.{type HttpError}
import modem
import plinth/javascript/storage
import qs
import rada/date.{type Date}

pub type Flags {
  Flags(api_host: String, api_public_key: String)
}

pub type Model {
  Model(
    auth: Auth,
    categories: RemoteData(CategoryCollection),
    displayed_date: Date,
    flags: Flags,
    habits: RemoteData(HabitCollection),
    is_adding: Bool,
    login_form: LoginForm,
    modal: Modal,
    new_habit_form: NewHabitForm,
    new_category_form: NewCategoryForm,
    notices: List(Notice),
    selected_habit: Option(Habit),
    show_expanded_actions: Bool,
  )
}

fn new_model(flags: Flags, date: Date) -> Model {
  Model(
    auth: Unauthenticated,
    categories: RemoteDataNotAsked,
    displayed_date: date,
    flags:,
    habits: RemoteDataNotAsked,
    is_adding: False,
    login_form: new_login_form(),
    modal: ModalNone,
    new_category_form: new_category_form(),
    new_habit_form: new_habit_form(),
    notices: [],
    selected_habit: None,
    show_expanded_actions: False,
  )
}

pub type Modal {
  ModalNone
  ModalDeleteHabit(Habit)
}

pub type RemoteData(data) {
  RemoteDataNotAsked
  RemoteDataLoading
  RemoteDataSuccess(data)
  RemoteDataFailure(String)
}

pub type Auth {
  Unauthenticated
  Authenticated(data: SessionData)
}

pub type LoginForm {
  LoginForm(email: String, password: String)
}

pub fn new_login_form() -> LoginForm {
  LoginForm(email: "", password: "")
}

pub type NewHabitForm {
  NewHabitForm(label: String)
}

fn new_habit_form() -> NewHabitForm {
  NewHabitForm(label: "")
}

pub type NewCategoryForm {
  NewCategoryForm(label: String)
}

fn new_category_form() -> NewCategoryForm {
  NewCategoryForm(label: "")
}

pub type Notice {
  Notice(message: String)
}

pub type CategoryCollection {
  CategoryCollection(items: List(Category))
}

pub type Category {
  Category(id: String, label: String)
}

pub type Categorized {
  Categorized(Category)
  Uncategorized
}

pub type HabitCollection {
  HabitCollection(date: Date, items: List(Habit))
}

pub type Habit {
  Habit(
    category_id: Option(String),
    checks: List(Check),
    id: String,
    label: String,
    started_at: Date,
    stopped_at: Option(Date),
  )
}

pub type Check {
  Check(date: Date)
}

fn category_decoder() -> dynamic.Decoder(Category) {
  dynamic.decode2(
    Category,
    dynamic.field("id", dynamic.string),
    dynamic.field("label", dynamic.string),
  )
}

fn categories_decoder() -> dynamic.Decoder(List(Category)) {
  dynamic.list(category_decoder())
}

fn habit_decoder() -> dynamic.Decoder(Habit) {
  dynamic.decode6(
    Habit,
    dynamic.field("category_id", dynamic.optional(dynamic.string)),
    dynamic.field("checks", dynamic.list(check_decoder())),
    dynamic.field("id", dynamic.string),
    dynamic.field("label", dynamic.string),
    dynamic.field("started_at", date_decoder),
    dynamic.field("stopped_at", dynamic.optional(date_decoder)),
  )
}

fn habits_decoder() -> dynamic.Decoder(List(Habit)) {
  dynamic.list(habit_decoder())
}

fn check_decoder() -> dynamic.Decoder(Check) {
  dynamic.decode1(Check, dynamic.field("date", date_decoder))
}

fn date_decoder(
  value: dynamic.Dynamic,
) -> Result(Date, List(dynamic.DecodeError)) {
  dynamic.string(value)
  |> result.then(fn(s) {
    date.from_iso_string(s)
    |> result.map_error(fn(e) { [dynamic.DecodeError(e, s, [])] })
  })
}

fn init(flags: Flags) -> #(Model, effect.Effect(Msg)) {
  let displayed_date = case modem.initial_uri() {
    Ok(uri) -> {
      case get_date_from_uri(uri) {
        Ok(date) -> date
        Error(_) -> date.today()
      }
    }
    Error(_) -> date.today()
  }
  let effects = effect.batch([modem.init(on_url_change), get_session()])
  #(new_model(flags, displayed_date), effects)
}

fn on_url_change(uri: Uri) -> Msg {
  OnRouteChange(uri)
}

pub type Msg {
  UnauthenticatedMsg(UnauthenticatedMsg)
  AuthenticatedMsg(SessionData, AuthenticatedMsg)
  OnRouteChange(Uri)
}

pub type UnauthenticatedMsg {
  ApiReturnedSessionData(Result(SessionData, HttpError))
  ClickedLogin
  ChangedEmail(String)
  ChangedPassword(String)
  GotSessionDataFromLS(SessionData)
}

pub type AuthenticatedMsg {
  ApiCreatedHabit(Result(Nil, HttpError))
  ApiCreatedCategory(Result(Nil, HttpError))
  ApiArchivedHabit(Habit, Date, Result(Nil, HttpError))
  ApiDeletedHabit(Habit, Result(Nil, HttpError))
  ApiReturnedHabits(Date, Result(List(Habit), HttpError))
  ApiReturnedCategories(Result(List(Category), HttpError))
  ApiToggledHabit(Habit, Date, Bool, Result(Nil, HttpError))
  ApiUnarchivedHabit(Habit, Result(Nil, HttpError))
  NewHabitFormSubmitted
  NewHabitLabelChanged(String)
  NewCategoryFormSubmitted
  NewCategoryLabelChanged(String)
  SelectedCategoryToMoveHabitTo(Category, Habit)
  UserArchivedHabit(Habit, Date)
  UserDeletedHabit(Habit)
  UserDeletedHabitCancelled
  UserDeletedHabitCommitted(Habit)
  UserSelectedHabit(Option(Habit))
  UserToggledExpandedActions(Bool)
  UserToggledHabit(Habit, Bool)
  UserUnarchivedHabit(Habit)
}

type Returns =
  #(Model, effect.Effect(Msg))

pub fn main(flags: dynamic.Dynamic) {
  let app = lustre.application(init, update, view)
  let assert Ok(flags) = flags_decoder()(flags)
  let assert Ok(_) = lustre.start(app, "#app", flags)

  Nil
}

pub fn update(model: Model, msg: Msg) -> Returns {
  case msg {
    UnauthenticatedMsg(unauth_msg) -> update_unauthenticated(model, unauth_msg)
    AuthenticatedMsg(session, auth_msg) ->
      update_authenticated(session, model, auth_msg)
    OnRouteChange(uri) -> {
      case get_date_from_uri(uri) {
        Ok(date) -> {
          #(Model(..model, displayed_date: date), effect.none())
          |> return.then(do_if_authenticated(_, fetch_data_for_displayed_date))
        }
        Error(_) -> #(model, effect.none())
      }
    }
  }
}

fn do_if_authenticated(
  model: Model,
  do: fn(Model, SessionData) -> Returns,
) -> Returns {
  case model.auth {
    Authenticated(session) -> do(model, session)
    Unauthenticated -> #(model, effect.none())
  }
}

fn get_date_from_uri(uri: Uri) -> Result(Date, String) {
  let maybe_query = uri.query |> option.to_result("Query not found")

  use query_str <- try(maybe_query)

  use query <- try(qs.default_parse(query_str))

  use dates_str <- try(qs.get(query, "date"))

  use date_str <- try(
    list.first(dates_str)
    |> result.replace_error("First date not found"),
  )

  date.from_iso_string(date_str)
}

pub fn update_unauthenticated(model: Model, msg: UnauthenticatedMsg) -> Returns {
  case msg {
    ApiReturnedSessionData(result) -> on_api_returned_auth_data(model, result)

    ChangedEmail(email) -> #(
      Model(..model, login_form: LoginForm(..model.login_form, email: email)),
      effect.none(),
    )
    ChangedPassword(password) -> #(
      Model(
        ..model,
        login_form: LoginForm(..model.login_form, password: password),
      ),
      effect.none(),
    )
    ClickedLogin -> {
      io.debug("Clicked login")
      #(model, login(model))
    }
    GotSessionDataFromLS(session) -> {
      case check_session_is_valid(session) {
        True -> {
          #(Model(..model, auth: Authenticated(session)), effect.none())
          |> return.then(fetch_data_for_displayed_date(_, session))
        }
        False -> #(Model(..model, auth: Unauthenticated), effect.none())
      }
    }
  }
}

pub fn update_authenticated(
  session: SessionData,
  model: Model,
  msg: AuthenticatedMsg,
) -> Returns {
  case msg {
    ApiReturnedHabits(date, result) -> {
      case result {
        Ok(habits) -> {
          let collection = HabitCollection(date, habits)
          #(
            Model(..model, habits: RemoteDataSuccess(collection)),
            effect.none(),
          )
        }
        Error(error) -> {
          io.debug(error)
          #(
            Model(
              ..model,
              habits: RemoteDataFailure(http_error_to_string(error)),
            ),
            effect.none(),
          )
        }
      }
    }
    ApiReturnedCategories(result) -> {
      case result {
        Ok(categories) -> {
          let collection = CategoryCollection(categories)
          #(
            Model(..model, categories: RemoteDataSuccess(collection)),
            effect.none(),
          )
        }
        Error(error) -> {
          io.debug(error)
          #(
            Model(
              ..model,
              habits: RemoteDataFailure(http_error_to_string(error)),
            ),
            effect.none(),
          )
        }
      }
    }
    ApiCreatedCategory(_result) -> {
      #(Model(..model, new_category_form: new_category_form()), effect.none())
      |> return.then(fetch_data_for_displayed_date(_, session))
    }
    ApiCreatedHabit(_result) -> {
      #(
        Model(..model, new_habit_form: new_habit_form(), is_adding: False),
        effect.none(),
      )
      |> return.then(fetch_data_for_displayed_date(_, session))
    }
    ApiArchivedHabit(_habit, _date, _result) -> {
      #(model, effect.none())
      |> return.then(fetch_data_for_displayed_date(_, session))
    }
    ApiDeletedHabit(_habit, _result) -> {
      #(model, effect.none())
      |> return.then(fetch_data_for_displayed_date(_, session))
    }
    ApiUnarchivedHabit(_habit, _result) -> {
      #(model, effect.none())
      |> return.then(fetch_data_for_displayed_date(_, session))
    }
    ApiToggledHabit(_habit, _date, _state, _result) -> {
      #(model, effect.none())
    }
    NewHabitLabelChanged(label) -> #(
      Model(..model, new_habit_form: NewHabitForm(label: label)),
      effect.none(),
    )
    NewHabitFormSubmitted -> {
      #(Model(..model, is_adding: True), create_habit(model, session))
    }
    NewCategoryLabelChanged(label) -> {
      #(
        Model(..model, new_category_form: NewCategoryForm(label:)),
        effect.none(),
      )
    }
    NewCategoryFormSubmitted -> {
      #(model, create_category(model, session))
    }
    SelectedCategoryToMoveHabitTo(category, habit) -> {
      // TODO
      #(model, effect.none())
    }
    UserArchivedHabit(habit, date) -> {
      #(model, archive_habit(model, session, habit, date))
    }
    UserDeletedHabit(habit) -> {
      #(Model(..model, modal: ModalDeleteHabit(habit)), effect.none())
    }
    UserDeletedHabitCancelled -> {
      #(Model(..model, modal: ModalNone), effect.none())
    }
    UserDeletedHabitCommitted(habit) -> {
      #(Model(..model, modal: ModalNone), delete_habit(model, session, habit))
    }
    UserToggledExpandedActions(state) -> {
      #(Model(..model, show_expanded_actions: state), effect.none())
    }
    UserUnarchivedHabit(habit) -> {
      #(model, unarchive_habit(model, session, habit))
    }
    UserSelectedHabit(habit) -> {
      #(Model(..model, selected_habit: habit), effect.none())
    }
    UserToggledHabit(habit, state) -> {
      #(model, toggle_check(model, session, habit, state))
    }
  }
}

fn on_api_returned_auth_data(
  model: Model,
  result: Result(SessionData, HttpError),
) -> Returns {
  case result {
    Ok(session) ->
      #(Model(..model, auth: Authenticated(session)), store_session(session))
      |> return.then(fetch_data_for_displayed_date(_, session))
    Error(error) -> #(
      Model(..model, notices: [Notice(http_error_to_string(error))]),
      effect.none(),
    )
  }
}

fn login(model: Model) -> effect.Effect(Msg) {
  let expect =
    lustre_http.expect_json(session_data_decoder(), ApiReturnedSessionData)

  let payload =
    json.object([
      #("email", json.string(model.login_form.email)),
      #("password", json.string(model.login_form.password)),
    ])

  // let url = api_login_url(model.flags)

  io.debug(payload)

  build_api_request(
    flags: model.flags,
    method: Post,
    path: "/auth/v1/token",
    query: [#("grant_type", "password")],
    payload: Some(payload),
  )
  |> lustre_http.send(expect)
  |> effect.map(UnauthenticatedMsg)
}

fn get_session() -> effect.Effect(Msg) {
  case get_session_do() {
    Ok(session_data) ->
      effect.from(fn(dispatch) { dispatch(GotSessionDataFromLS(session_data)) })
      |> effect.map(UnauthenticatedMsg)
    Error(err) -> {
      io.debug(err)
      effect.none()
    }
  }
}

fn get_session_do() -> Result(SessionData, String) {
  use local_storage <- try(
    storage.local()
    |> result.replace_error("Unable to open local storage"),
  )

  use json_string <- try(
    storage.get_item(local_storage, "session")
    |> result.replace_error("Unable to get session data from local storage"),
  )

  use data <- try(
    json.decode(json_string, session_data_decoder())
    |> result.map_error(json_error_to_string),
  )

  Ok(data)
}

fn store_session(data: SessionData) -> effect.Effect(Msg) {
  case store_session_do(data) {
    Ok(_) -> {
      effect.none()
    }
    Error(_) -> {
      io.debug("Failed to open local storage")
      effect.none()
    }
  }
}

fn store_session_do(data: SessionData) -> Result(Nil, String) {
  use local_storage <- try(
    storage.local()
    |> result.replace_error("Unable to open local storage"),
  )

  let json_string = session_encode(data) |> json.to_string

  storage.set_item(local_storage, "session", json_string)
  |> result.replace_error("Unable to store session data in local storage")
}

fn fetch_data_for_displayed_date(model: Model, session: SessionData) -> Returns {
  fetch_categories(model, session)
  |> return.then(fetch_habits_for_displayed_date(_, session))
}

fn fetch_categories(model: Model, session: SessionData) -> Returns {
  let expect =
    lustre_http.expect_json(categories_decoder(), fn(result) {
      AuthenticatedMsg(session, ApiReturnedCategories(result))
    })

  let effect =
    api_crud_request(
      flags: model.flags,
      method: Get,
      path: "/categories",
      payload: None,
      query: [],
      session:,
    )
    |> lustre_http.send(expect)

  #(Model(..model, categories: RemoteDataLoading), effect)
}

fn fetch_habits_for_displayed_date(
  model: Model,
  session: SessionData,
) -> Returns {
  let date = model.displayed_date

  let expect =
    lustre_http.expect_json(habits_decoder(), fn(result) {
      AuthenticatedMsg(session, ApiReturnedHabits(date, result))
    })

  let date_str = date_to_string(date)

  let effect =
    api_crud_request(
      flags: model.flags,
      method: Get,
      path: "/habits",
      payload: None,
      query: [
        #("started_at", "lte." <> date_str),
        #("or", "(stopped_at.is.null,stopped_at.gte." <> date_str <> ")"),
        #("select", "*,checks(*)"),
        #("checks.date", "eq." <> date_str),
      ],
      session:,
    )
    |> lustre_http.send(expect)

  #(Model(..model, habits: RemoteDataLoading), effect)
}

fn create_category(model: Model, session: SessionData) -> effect.Effect(Msg) {
  let expect = lustre_http.expect_anything(ApiCreatedCategory)

  let payload =
    json.object([
      //
      #("label", json.string(model.new_category_form.label)),
    ])

  api_crud_request(
    flags: model.flags,
    method: Post,
    path: "/categories",
    payload: Some(payload),
    query: [],
    session:,
  )
  |> lustre_http.send(expect)
  |> effect.map(AuthenticatedMsg(session, _))
}

fn create_habit(model: Model, session: SessionData) -> effect.Effect(Msg) {
  let expect = lustre_http.expect_anything(ApiCreatedHabit)

  let payload =
    json.object([
      //
      #("label", json.string(model.new_habit_form.label)),
      #("started_at", json.string(date_to_string(model.displayed_date))),
    ])

  api_crud_request(
    flags: model.flags,
    method: Post,
    path: "/habits",
    payload: Some(payload),
    query: [],
    session:,
  )
  |> lustre_http.send(expect)
  |> effect.map(AuthenticatedMsg(session, _))
}

fn delete_habit(
  model: Model,
  session: SessionData,
  habit: Habit,
) -> effect.Effect(Msg) {
  let expect = lustre_http.expect_anything(ApiDeletedHabit(habit, _))

  api_crud_request(
    flags: model.flags,
    method: http.Delete,
    path: "/habits",
    payload: None,
    query: [#("id", "eq." <> habit.id)],
    session:,
  )
  |> lustre_http.send(expect)
  |> effect.map(AuthenticatedMsg(session, _))
}

fn toggle_check(
  model: Model,
  session: SessionData,
  habit: Habit,
  state: Bool,
) -> effect.Effect(Msg) {
  let message = ApiToggledHabit(habit, model.displayed_date, state, _)
  let expect = lustre_http.expect_anything(message)

  let date_str = date_to_string(model.displayed_date)

  let payload =
    json.object([
      //
      #("habit_id", json.string(habit.id)),
      #("date", json.string(date_str)),
    ])

  let request = case state {
    True ->
      api_crud_request(
        flags: model.flags,
        method: Post,
        path: "/checks",
        payload: Some(payload),
        query: [],
        session:,
      )

    False ->
      api_crud_request(
        flags: model.flags,
        method: http.Delete,
        path: "/checks",
        payload: None,
        query: [#("habit_id", "eq." <> habit.id), #("date", "eq." <> date_str)],
        session:,
      )
  }

  request
  |> lustre_http.send(expect)
  |> effect.map(AuthenticatedMsg(session, _))
}

fn archive_habit(model: Model, session: SessionData, habit: Habit, date: Date) {
  let message = ApiArchivedHabit(habit, date, _)
  let expect = lustre_http.expect_anything(message)
  let date_str = date_to_string(date)

  let payload =
    json.object([
      //
      #("stopped_at", json.string(date_str)),
    ])

  let request =
    api_crud_request(
      flags: model.flags,
      method: http.Patch,
      path: "/habits",
      payload: Some(payload),
      query: [#("id", "eq." <> habit.id)],
      session:,
    )

  request
  |> lustre_http.send(expect)
  |> effect.map(AuthenticatedMsg(session, _))
}

fn unarchive_habit(model: Model, session: SessionData, habit: Habit) {
  let message = ApiUnarchivedHabit(habit, _)
  let expect = lustre_http.expect_anything(message)

  let payload =
    json.object([
      //
      #("stopped_at", json.null()),
    ])

  let request =
    api_crud_request(
      flags: model.flags,
      method: http.Patch,
      path: "/habits",
      payload: Some(payload),
      query: [#("id", "eq." <> habit.id)],
      session:,
    )

  request
  |> lustre_http.send(expect)
  |> effect.map(AuthenticatedMsg(session, _))
}

/// Decoders
pub fn flags_decoder() {
  dynamic.decode2(
    Flags,
    dynamic.field("apiHost", dynamic.string),
    dynamic.field("apiPublicKey", dynamic.string),
  )
}

pub type SessionData {
  SessionData(
    access_token: String,
    refresh_token: String,
    expires_at: Int,
    user: User,
  )
}

pub type User {
  User(id: String, email: String)
}

pub fn session_data_decoder() {
  dynamic.decode4(
    SessionData,
    dynamic.field("access_token", dynamic.string),
    dynamic.field("refresh_token", dynamic.string),
    dynamic.field("expires_at", dynamic.int),
    dynamic.field("user", session_user_decoder()),
  )
}

pub fn session_encode(data: SessionData) {
  json.object([
    #("access_token", json.string(data.access_token)),
    #("refresh_token", json.string(data.refresh_token)),
    #("expires_at", json.int(data.expires_at)),
    #("user", session_user_encode(data.user)),
  ])
}

pub fn session_user_decoder() {
  dynamic.decode2(
    User,
    dynamic.field("id", dynamic.string),
    dynamic.field("email", dynamic.string),
  )
}

pub fn session_user_encode(user: User) {
  json.object([
    #("id", json.string(user.id)),
    #("email", json.string(user.email)),
  ])
}

/// Views
pub fn view(model: Model) -> element.Element(Msg) {
  let today = date.today()

  case model.auth {
    Unauthenticated ->
      view_unauthenticated(model) |> element.map(UnauthenticatedMsg)

    Authenticated(session) -> {
      case check_session_is_valid(session) {
        True -> {
          view_authenticated(model, session, today)
          |> element.map(AuthenticatedMsg(session, _))
        }
        False -> {
          io.debug("Session expired")
          view_unauthenticated(model) |> element.map(UnauthenticatedMsg)
        }
      }
    }
  }
}

fn check_session_is_valid(session: SessionData) -> Bool {
  let now = birl.now() |> birl.to_unix
  now < session.expires_at
}

fn view_unauthenticated(model: Model) -> Element(UnauthenticatedMsg) {
  html.main([class("pt-4 flex justify-center")], [view_login_form(model)])
}

fn view_login_form(model: Model) {
  html.form([event.on_submit(ClickedLogin), class("space-y-4")], [
    div([], [
      html.label([class("block")], [text("Email")]),
      components.input([
        class("t-input-email"),
        attr.type_("text"),
        attr.name("email"),
        attr.value(model.login_form.email),
        event.on_input(ChangedEmail),
      ]),
    ]),
    div([], [
      html.label([class("block")], [text("Passsword")]),
      components.input([
        class("t-input-password"),
        attr.type_("password"),
        attr.name("password"),
        attr.value(model.login_form.password),
        event.on_input(ChangedPassword),
      ]),
    ]),
    div([], [
      buttons.new(buttons.ActionSubmit)
      |> buttons.with_label("Login")
      |> buttons.view,
    ]),
  ])
}

fn view_authenticated(
  model: Model,
  session: SessionData,
  today: Date,
) -> Element(AuthenticatedMsg) {
  html.main([], [
    view_header(model, session),
    //
    view_pagination(model, today),
    view_actions(model, session),
    view_habits(model, today),
    view_maybe_modal(model),
  ])
}

fn view_maybe_modal(model: Model) {
  case model.modal {
    ModalNone -> element.none()
    ModalDeleteHabit(habit) -> view_modal_delete_habit(model, habit)
  }
}

fn view_modal_delete_habit(_model: Model, habit: Habit) {
  components.modal([
    html.p([class("pb-2")], [
      text("Completely delete this habit? There is no undo."),
    ]),
    html.div([class("py-2 space-x-3 text-right")], [
      buttons.new(buttons.ActionClick(UserDeletedHabitCancelled))
        |> buttons.with_label("Cancel")
        |> buttons.view,
      buttons.new(buttons.ActionClick(UserDeletedHabitCommitted(habit)))
        |> buttons.with_label("Delete")
        |> buttons.with_variant(buttons.VariantDanger)
        |> buttons.view,
    ]),
  ])
}

fn view_header(_model: Model, session: SessionData) {
  html.header([class("t-header p-2 bg-black text-white")], [
    text(session.user.email),
    //
  ])
}

fn view_actions(model: Model, _session: SessionData) {
  html.section([class("t-panel-actions px-4 bg-slate-100")], [
    //
    div([class("flex justify-between py-3")], [
      view_new_habit_form(model),
      div([], [view_actions_btn_expand(model)]),
    ]),
    view_actions_expanded(model),
  ])
}

fn view_new_habit_form(model: Model) {
  html.form(
    [
      //
      class("t-new-habit-form flex space-x-2 items-center"),
      event.on_submit(NewHabitFormSubmitted),
    ],
    [
      //
      components.input([
        class("t-input-new"),
        attr.type_("text"),
        attr.name("label"),
        attr.value(model.new_habit_form.label),
        event.on_input(NewHabitLabelChanged),
      ]),
      buttons.new(buttons.ActionSubmit)
        |> buttons.with_label("Add Habit")
        |> buttons.with_icon_left(icons.Plus)
        |> buttons.with_is_disabled(model.is_adding)
        |> buttons.view,
    ],
  )
}

fn view_new_category_form(model: Model) {
  html.form(
    [
      //
      class("t-new-category-form flex space-x-2 items-center"),
      event.on_submit(NewCategoryFormSubmitted),
    ],
    [
      //
      components.input([
        class("t-input-new"),
        attr.type_("text"),
        attr.name("label"),
        attr.value(model.new_category_form.label),
        event.on_input(NewCategoryLabelChanged),
      ]),
      buttons.new(buttons.ActionSubmit)
        |> buttons.with_label("Add Category")
        |> buttons.with_icon_left(icons.Plus)
        |> buttons.with_variant(buttons.VariantSecondary)
        |> buttons.with_is_disabled(model.is_adding)
        |> buttons.view,
    ],
  )
}

fn view_actions_btn_expand(model: Model) {
  let next_state = !model.show_expanded_actions

  let icon = case model.show_expanded_actions {
    True -> icons.ChevronDown
    False -> icons.ChevronRight
  }
  buttons.new(buttons.ActionClick(UserToggledExpandedActions(next_state)))
  |> buttons.with_icon_left(icon)
  |> buttons.with_variant(buttons.VariantUnfilled)
  |> buttons.view
}

fn view_actions_expanded(model: Model) {
  let clases =
    attr.classes([
      #("t-expanded-actions py-2", True),
      #("hidden", !model.show_expanded_actions),
    ])

  div([clases], [view_new_category_form(model)])
}

fn date_to_query_string(date: Date) -> String {
  let str = date.to_iso_string(date)

  qs.empty()
  |> qs.insert("date", [str])
  |> qs.default_serialize()
}

fn view_pagination(model: Model, today: Date) {
  let yesterday = date.add(model.displayed_date, -1, date.Days)

  let tomorrow = date.add(model.displayed_date, 1, date.Days)

  let today = date_to_query_string(today)

  let prev = date_to_query_string(yesterday)

  let next = date_to_query_string(tomorrow)

  html.section(
    [
      class(
        "t-pagination px-4 py-4 flex justify-between items-center bg-slate-200",
      ),
    ],
    [
      div([class("font-semibold text-2xl")], [
        text(date_to_string(model.displayed_date)),
      ]),
      div([class("py-1 space-x-4 flex items-center")], [
        buttons.new(buttons.ActionLink(today))
          |> buttons.with_label("Today")
          |> buttons.with_variant(buttons.VariantOutlined)
          |> buttons.view,
        //
        buttons.new(buttons.ActionLink(prev))
          |> buttons.with_attrs([class("t-btn-prev px-1")])
          |> buttons.with_icon_left(icons.ChevronLeft)
          |> buttons.with_variant(buttons.VariantOutlined)
          |> buttons.view,
        //
        buttons.new(buttons.ActionLink(next))
          |> buttons.with_attrs([class("t-btn-next px-1")])
          |> buttons.with_icon_left(icons.ChevronRight)
          |> buttons.with_variant(buttons.VariantOutlined)
          |> buttons.view,
      ]),
    ],
  )
}

fn view_habits(model: Model, today: Date) {
  case model.habits {
    RemoteDataNotAsked | RemoteDataLoading ->
      view_habits_wrapper([text("Loading habits...")])
    RemoteDataSuccess(habits) -> {
      case model.categories {
        RemoteDataNotAsked | RemoteDataLoading ->
          view_habits_wrapper([text("Loading categories...")])
        RemoteDataSuccess(categories) -> {
          view_habits_with_data(categories, habits, model.selected_habit, today)
        }
        RemoteDataFailure(error) -> text(error)
      }
    }
    RemoteDataFailure(error) -> text(error)
  }
}

fn view_habits_wrapper(children) {
  html.section([class("t-habits-wrapper pl-4 pr-3 py-4")], children)
}

fn view_habits_with_data(
  categories: CategoryCollection,
  habit_collection: HabitCollection,
  selected_habit: Option(Habit),
  today: Date,
) {
  let sorted =
    habit_collection.items
    |> list.sort(by: fn(a, b) {
      string.compare(a.label |> string.lowercase, b.label |> string.lowercase)
    })

  let all_categories =
    categories.items
    |> list.map(Categorized)
    |> list.append([Uncategorized])

  view_habits_wrapper([
    html.table([class("t-habits-list w-full table-auto")], [
      html.tbody(
        [],
        list.flat_map(all_categories, view_category(
          _,
          habit_collection.date,
          today,
          selected_habit,
          sorted,
        )),
      ),
    ]),
  ])
}

fn col1_classes() {
  class("max-w-5")
}

fn view_category(
  categorized: Categorized,
  date: Date,
  today: Date,
  selected_habit: Option(Habit),
  sorted_habits: List(Habit),
) {
  let category = case categorized {
    Categorized(category) -> Some(category)
    Uncategorized -> None
  }

  let #(category_id, category_label) = case category {
    Some(category) -> #(Some(category.id), category.label)
    None -> #(None, "Uncategorized")
  }

  let relevant_habits =
    sorted_habits
    |> list.filter(fn(habit) { habit.category_id == category_id })

  let move_here = case selected_habit {
    Some(habit) -> {
      case category {
        None -> element.none()
        Some(category) -> {
          case habit.category_id == Some(category.id) {
            True -> element.none()
            False -> {
              html.tr([], [
                html.td([], []),
                html.td([attr.attribute("colspan", "2")], [
                  buttons.new(
                    buttons.ActionClick(SelectedCategoryToMoveHabitTo(
                      category,
                      habit,
                    )),
                  )
                  |> buttons.with_label("Move here")
                  |> buttons.with_variant(buttons.VariantOutlined)
                  |> buttons.view,
                ]),
              ])
            }
          }
        }
      }
    }
    None -> element.none()
  }

  let selected_habit_id = option.map(selected_habit, fn(h) { h.id })

  let habit_rows = case relevant_habits == [] {
    True -> [
      html.tr([], [
        html.td([col1_classes()], []),
        html.td([class("text-slate-300 text-lg")], [text("Empty")]),
        html.td([], []),
      ]),
    ]
    False -> {
      relevant_habits
      |> list.flat_map(view_habit(_, date, today, selected_habit_id))
    }
  }

  [
    html.tr([], [
      html.th(
        [class("text-left text-slate-600 py-2"), attr.attribute("colspan", "3")],
        [text(category_label)],
      ),
    ]),
    move_here,
    ..habit_rows
  ]
}

fn view_habit(
  habit: Habit,
  date: Date,
  today: Date,
  selected_habit_id: Option(String),
) -> List(Element(AuthenticatedMsg)) {
  let is_checked =
    habit.checks
    |> list.any(fn(check) { check.date == date })

  let is_selected = selected_habit_id == Some(habit.id)

  let is_habit_for_today = date == today
  let is_habit_stopped = habit.stopped_at == Some(date)

  let radio_click = case is_selected {
    True -> UserSelectedHabit(None)
    False -> UserSelectedHabit(Some(habit))
  }

  let btn_move =
    html.input([
      event.on_click(radio_click),
      attr.type_("radio"),
      attr.checked(is_selected),
      attr.name("move"),
      attr.value(habit.id),
      class("w-5 h-5"),
    ])

  let btn_archive = case is_habit_for_today && !is_habit_stopped {
    True -> {
      buttons.new(buttons.ActionClick(UserArchivedHabit(habit, date)))
      |> buttons.with_icon_left(icons.Archive)
      |> buttons.with_variant(buttons.VariantUnfilled)
      |> buttons.with_attrs([class("t-btn-archive")])
      |> buttons.view
    }
    False -> {
      text("")
    }
  }

  let btn_unarchive = case is_habit_stopped {
    True ->
      buttons.new(buttons.ActionClick(UserUnarchivedHabit(habit)))
      |> buttons.with_icon_left(icons.Unarchive)
      |> buttons.with_variant(buttons.VariantUnfilled)
      |> buttons.with_attrs([class("t-btn-unarchive text-slate-500")])
      |> buttons.view

    False -> text("")
  }

  let btn_delete =
    buttons.new(buttons.ActionClick(UserDeletedHabit(habit)))
    |> buttons.with_icon_left(icons.Trash)
    |> buttons.with_variant(buttons.VariantUnfilled)
    |> buttons.with_attrs([class("t-btn-delete")])
    |> buttons.view

  let td_classes = case is_selected {
    True -> class("bg-slate-100")
    False -> class("")
  }

  let row1 =
    html.tr([class("t-habit")], [
      html.td([td_classes, col1_classes(), class("t-habit-check")], [
        html.input([
          class("h-5 w-5"),
          attr.type_("checkbox"),
          attr.checked(is_checked),
          event.on_check(UserToggledHabit(habit, _)),
        ]),
      ]),
      html.td([td_classes, class("t-habit-label pl-4 py-2")], [
        div([class("text-lg max-w-72 truncate")], [text(habit.label)]),
      ]),
      html.td(
        [td_classes, class("text-right"), style([#("max-width", "3rem")])],
        [btn_move],
      ),
    ])

  let row2 = case is_selected {
    True ->
      html.tr([class("bg-slate-100")], [
        html.td([class(""), attr.attribute("colspan", "3")], [
          div([class("flex items-center justify-end")], [
            btn_archive,
            btn_unarchive,
            btn_delete,
          ]),
        ]),
      ])
    False -> element.none()
  }

  [row1, row2]
}

/// Helpers
fn http_error_to_string(error: HttpError) -> String {
  case error {
    lustre_http.BadUrl(str) -> "BadUrl " <> str
    lustre_http.InternalServerError(str) -> "InternalServerError " <> str
    lustre_http.JsonError(err) -> json_error_to_string(err)
    lustre_http.NetworkError -> "NetworkError"
    lustre_http.NotFound -> "NotFound"
    lustre_http.OtherError(_code, str) -> "OtherError " <> str
    lustre_http.Unauthorized -> "Unauthorized"
  }
}

fn json_error_to_string(error: json.DecodeError) -> String {
  case error {
    json.UnexpectedEndOfInput -> "UnexpectedEndOfInput"
    json.UnexpectedByte(_, _) -> "UnexpectedByte"
    json.UnexpectedSequence(_, _) -> "UnexpectedSequence"
    json.UnexpectedFormat(_) -> "UnexpectedFormat"
  }
}

fn build_api_request(
  flags flags: Flags,
  method method: Method,
  path path: String,
  query query: List(#(String, String)),
  payload payload: Option(json.Json),
) -> Request(String) {
  request.new()
  |> request.set_method(method)
  |> request.set_scheme(Https)
  |> request.set_host(flags.api_host)
  |> request.set_path(path)
  |> request.set_query(query)
  |> maybe_add_payload(payload)
  |> request.set_header("apikey", flags.api_public_key)
  |> request.set_header("Authorization", "Bearer " <> flags.api_public_key)
  |> request.set_header("Content-Type", "application/json")
}

fn maybe_add_payload(
  req: Request(String),
  payload: Option(json.Json),
) -> Request(String) {
  case payload {
    Some(json) -> {
      let body = json.to_string(json)
      request.set_body(req, body)
    }
    None -> req
  }
}

fn api_crud_request(
  flags flags: Flags,
  method method: Method,
  path path: String,
  payload payload: Option(json.Json),
  query query: List(#(String, String)),
  session session: SessionData,
) -> Request(String) {
  build_api_request(
    flags: flags,
    method:,
    path: "/rest/v1" <> path,
    payload:,
    query:,
  )
  |> request.set_header("Authorization", "Bearer " <> session.access_token)
}

fn date_to_string(date: Date) -> String {
  date.to_iso_string(date)
}
