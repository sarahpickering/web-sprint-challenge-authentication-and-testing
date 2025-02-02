const db = require('../../data/dbConfig')

function getAll() {
    return db('users')
}

function findBy(filter) {
    return db('users').where(filter);
}

async function insert(user) {
    const [id] = await db('users').insert(user);
    return findBy({ id }).first();
}

module.exports = {
    getAll,
    insert,
    findBy
};