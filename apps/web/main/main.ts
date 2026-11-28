import { mount } from 'svelte';
import App from './interface/App.svelte';
import NotFound from './interface/NotFound.svelte';
import { isKnownPagePath } from './interface/routes';
import './interface/app.css';

const target = document.getElementById('app');

if (!target) {
  throw new Error('PrivaCage web root element is missing.');
}

mount(isKnownPagePath(window.location.pathname) ? App : NotFound, { target });
