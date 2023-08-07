/*
Assignment 5 Solution - Leave this if you want to use it for Assignment 6 - MS
*/
require('dotenv').config();
const express = require('express');
const store_service = require('./store-service');
const app = express();
const Sequelize = require('sequelize');
const port = process.env.PORT || 8080;
console.log('port', port);
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const clientSessions = require('client-sessions');
require('dotenv').config();
const upload = multer(); // no { storage: storage }
const exphbs = require('express-handlebars');
const authService = require('./auth-service');
const sequelize = new Sequelize(process.env.SEQUELIZE_USER, process.env.SEQUELIZE_DB,process.env.SEQUELIZE_PASSWORD, {
  host: process.env.SEQUELIZE_HOST,
  dialect: 'postgres',
  port: 5432,
  dialectOptions: {
      ssl: { rejectUnauthorized: false }
  },
  query: { raw: true }
})
sequelize
	.authenticate()
	.then(function () {
		console.log('Connection has been established successfully.');
	})
	.catch(function (err) {
		console.log('Unable to connect to the database:', err);
	});

app.engine(
	'.hbs',
	exphbs.engine({
		extname: '.hbs',
		helpers: {
			navLink: function (url, options) {
				return (
					'<li class="nav-item"><a ' +
					(url == app.locals.activeRoute
						? ' class="nav-link active"'
						: ' class="nav-link" ') +
					' href="' +
					url +
					'">' +
					options.fn(this) +
					'</a></li>'
				);
			},
			equal: function (lvalue, rvalue, options) {
				if (arguments.length < 3)
					throw new Error('Handlebars Helper equal needs 2 parameters');
				if (lvalue != rvalue) {
					return options.inverse(this);
				} else {
					return options.fn(this);
				}
			},
			formatDate: function (dateObj) {
				let year = dateObj.getFullYear();
				let month = (dateObj.getMonth() + 1).toString();
				let day = dateObj.getDate().toString();
				return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
			},
		},
	}),
);
app.set('view engine', '.hbs');

cloudinary.config({
	cloud_name: 'dbwcihww1',
	api_key: '384368237456848',
	api_secret: 'VIC5H8t5Iciyq_J_1HZEWeXnqQI',
});

app.use(function (req, res, next) {
	let route = req.path.substring(1);
	app.locals.activeRoute =
		'/' +
		(isNaN(route.split('/')[1])
			? route.replace(/\/(?!.*)/, '')
			: route.replace(/\/(.*)/, ''));
	app.locals.viewingCategory = req.query.category;
	next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(
	clientSessions({
		cookieName: 'session',
		secret: '1776feda-a2f5-43cd-9ee2-f50f7826aa5e',
		duration: 2 * 60 * 1000,
		activeDuration: 1000 * 60,
	}),
);
const validatLogin = (req, res, next) => {
	if (!req.session.user) {
		res.redirect('/login');
	} else {
		next();
	}
};
app.get('/', (req, res) => {
	res.redirect('/shop');
});

app.get('/items/add', validatLogin, (req, res) => {
	store_service
		.getCategories()
		.then((data) => {
			res.render('addItem', { categories: data });
		})
		.catch(() => {
			res.render('addItem', { categories: [] });
		});
});

app.get('/about', (req, res) => {
	console.log('test about');
	res.render('about');
});

// app.get('/shop', (req, res) => {
//   store_service.getPublishedItems().then((data)=>{
//     res.json(data)
//   }).catch((err)=>{
//     return {'message': err}
//   })
// });

app.get('/shop', async (req, res) => {
	// Declare an object to store properties for the view
	let viewData = {};

	try {
		// declare empty array to hold "post" objects
		let items = [];

		// if there's a "category" query, filter the returned posts by category
		if (req.query.category) {
			// Obtain the published "posts" by category
			items = await store_service.getPublishedItemsByCategory(
				req.query.category,
			);
		} else {
			// Obtain the published "items"
			items = await store_service.getPublishedItems();
		}

		// sort the published items by postDate
		items.sort((a, b) => new Date(b.postDate) - new Date(a.postDate));

		// get the latest post from the front of the list (element 0)
		let item = items[0];

		// store the "items" and "post" data in the viewData object (to be passed to the view)
		viewData.items = items;
		viewData.item = item;
	} catch (err) {
		viewData.message = 'no results';
	}

	try {
		// Obtain the full list of "categories"
		let categories = await store_service.getCategories();

		// store the "categories" data in the viewData object (to be passed to the view)
		viewData.categories = categories;
	} catch (err) {
		viewData.categoriesMessage = 'no results';
	}

	// render the "shop" view with all of the data (viewData)
	res.render('shop', { data: viewData });
});

app.get('/shop/:id', async (req, res) => {
	// Declare an object to store properties for the view
	let viewData = {};

	try {
		// declare empty array to hold "item" objects
		let items = [];

		// if there's a "category" query, filter the returned posts by category
		if (req.query.category) {
			// Obtain the published "posts" by category
			items = await store_service.getPublishedItemsByCategory(
				req.query.category,
			);
		} else {
			// Obtain the published "posts"
			items = await store_service.getPublishedItems();
		}

		// sort the published items by postDate
		items.sort((a, b) => new Date(b.postDate) - new Date(a.postDate));

		// store the "items" and "item" data in the viewData object (to be passed to the view)
		viewData.items = items;
	} catch (err) {
		viewData.message = 'no results';
	}

	try {
		// Obtain the item by "id"
		viewData.item = await store_service.getItemById(req.params.id);
	} catch (err) {
		viewData.message = 'no results';
	}

	try {
		// Obtain the full list of "categories"
		let categories = await store_service.getCategories();

		// store the "categories" data in the viewData object (to be passed to the view)
		viewData.categories = categories;
	} catch (err) {
		viewData.categoriesMessage = 'no results';
	}

	// render the "shop" view with all of the data (viewData)
	res.render('shop', { data: viewData });
});

app.get('/items', validatLogin, (req, res) => {
	const cat = req.query.category;
	const mDate = req.query.minDate;

	if (cat) {
		store_service
			.getItemsByCategory(cat)
			.then((data) => {
				res.render('items', { items: data });
			})
			.catch((err) => {
				return { message: err };
			});
	} else if (mDate) {
		store_service
			.getItemsByMinDate(mDate)
			.then((data) => {
				res.json(data);
			})
			.catch((err) => {
				return { message: err };
			});
	} else {
		store_service
			.getAllItems()
			.then((data) => {
				res.render('items', { items: data });
			})
			.catch((err) => {
				return { message: err };
			});
	}
});

app.get('/items/:value', validatLogin, (req, res) => {
	const value = parseInt(req.params.value, 10);
	store_service
		.getItemById(value)
		.then((data) => {
			res.json(data);
		})
		.catch((err) => {
			return { message: err };
		});
});

app.get('/categories', validatLogin, (req, res) => {
	store_service
		.getCategories()
		.then((data) => {
			res.render('categories', { items: data });
		})
		.catch((err) => {
			return { message: err };
		});
});

app.get('/categories/add', validatLogin, (req, res) => {
	res.render('addCategory');
});

app.post('/categories/add', validatLogin, (req, res) => {
	console.log(req.body);
	store_service.addCategory(req.body);
	res.redirect('/categories');
});

app.get('/categories/delete/:id', validatLogin, (req, res) => {
	const id = req.params.id;
	store_service
		.deleteCategoryById(id)
		.then(() => {
			res.redirect('/categories');
		})
		.catch(() => {
			res.status(500).send('Unable to Remove Category / Category not found)');
		});
});

app.get('/items/delete/:id', validatLogin, (req, res) => {
	const id = req.params.id;
	store_service
		.deletePostById(id)
		.then(() => {
			res.redirect('/items');
		})
		.catch(() => {
			res.status(500).send('Unable to Remove item / item not found)');
		});
});

app.post(
	'/items/add',
	validatLogin,
	upload.single('featureImage'),
	(req, res) => {
		if (req.file) {
			let streamUpload = (req) => {
				return new Promise((resolve, reject) => {
					let stream = cloudinary.uploader.upload_stream((error, result) => {
						if (result) {
							resolve(result);
						} else {
							reject(error);
						}
					});

					streamifier.createReadStream(req.file.buffer).pipe(stream);
				});
			};

			async function upload(req) {
				let result = await streamUpload(req);
				console.log(result);
				return result;
			}

			upload(req).then((uploaded) => {
				processItem(uploaded.url);
			});
		} else {
			processItem('');
		}

		function processItem(imageUrl) {
			req.body.featureImage = imageUrl;

			// TODO: Process the req.body and add it as a new Item before redirecting to /items
			store_service
				.addItem(req.body)
				.then(() => {
					res.redirect('/items');
				})
				.catch((error) => {
					console.log(error);
					res.redirect('/items');
				});
		}
	},
);
app.get('/login', (req, res) => {
	res.render('login');
});

app.post('/login', async (req, res) => {
	try {
		const { username, password } = req.body;
		const userAgent = req.get('User-Agent');
		const user = await authService.checkUser({ username, password, userAgent });
		req.session.user = {
			username: user.username,
			email: user.email,
			loginHistory: user.loginHistory,
		};
		res.redirect('/items');
	} catch (err) {
		res.render('login', { message: err });
	}
});

app.get('/register', (req, res) => {
	res.render('register');
});

app.post('/register', async (req, res) => {
	try {
		const { username, password, email, password2 } = req.body;
		const userAgent = req.get('User-Agent');
		const user = await authService.registerUser({
			username,
			password,
			email,
			userAgent,
			password2,
		});
		req.session.user = {
			username: user.username,
			email,
			loginHistory: user.loginHistory,
		};

		res.redirect('/items');
	} catch (err) {
		res.render('register', { message: err });
	}
});

app.get('/logout', (req, res) => {
	req.session.reset();
	res.redirect('/');
});

app.get('/userHistory', validatLogin, async (req, res) => {
	try {
		console.log(req.session.user);
		res.render('userHistory', { ...req.session.user });
	} catch (err) {
		res.render('userHistory', { message: err });
	}
});

app.get('*', function (req, res) {
	res.render('404');
});

function onHTTPstart() {
	console.log('server started on port: ' + port);
}

store_service
	.initialize()
	.then(authService.initialize)
	.then(function () {
		app.listen(port, onHTTPstart);
	})
	.catch(function (err) {
		console.log('unable to start ' + err);
	});

app.use((req, res) => {
	res.status(404).send('Page does not exist');
});
