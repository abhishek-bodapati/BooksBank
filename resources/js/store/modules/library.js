import axios from 'axios'

// state
export const state = {
  searchResult: [],
  searchTitle: '',
  currentLocation: {
    lat: null,
    lon: null
  },
  conditions: [
    { name: 'Very Good', description: 'Shows signs of wear. May have minor defects: clipped or chipped dust jacket; owner’s inscription; remainder mark; minor foxing or bumping. Used textbooks do not come with supplemental materials.' },
    { name: 'Good', description: 'Average used book with all pages present. May have any of the defects above to a greater degree, including highlighting, library markings, or loose bindings. Rare and collectible books may have cocked spine, cracked hinges, water stains; torn or repaired dust jacket.' },
    { name: 'Acceptable', description: 'May be very worn, soiled, torn, or barely holding together. Used textbooks do not come with supplemental materials.' },
    { name: 'Poor', description: 'May have extensive damage from moisture or insects; detached boards; parts may be missing; marginally salable unless very unusual. Used textbooks do not come with supplemental materials.' }
  ],
  loading: false
}

// getters
export const getters = {
  searchedBook: state => {
    if (!state.searchTitle) return state.searchResult

    return state.searchResult.filter(result => result.book.title.toLowerCase().includes(state.searchTitle.toLowerCase()))
  },
  otherBooks: state => {
    if (!state.searchTitle) return []

    return state.searchResult.filter(result => !result.book.title.toLowerCase().includes(state.searchTitle.toLowerCase()))
  },
  loading: state => state.loading
}

// mutations
export const mutations = {
  UPDATE_SEARCH_RESULT (state, result) {
    state.searchResult = result
  },
  RESET_SEARCH_RESULT (state) {
    state.searchResult = []
  },
  SET_SEARCH_TITLE (state, title) {
    state.searchTitle = title
  },
  SET_LOADING (state, value) {
    state.loading = value
  }
}

// actions
export const actions = {
  async search ({ commit, dispatch }, { searchTitle, latitude, longitude, radius }) {
    commit('SET_LOADING', true)
    commit('RESET_SEARCH_RESULT')
    const { data } = await axios.get(`/api/library/${latitude}/${longitude}/${radius}`)
    commit('SET_LOADING', false)
    if (!data) return
    if (searchTitle && searchTitle !== 'All') commit('SET_SEARCH_TITLE', searchTitle)
    commit('UPDATE_SEARCH_RESULT', data)
  }
}
