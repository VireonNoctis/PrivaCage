import { mount } from 'svelte';
import App from './interface/App.svelte';
import './interface/app.css';

const target = document.getElementById('app');

if (!target) {
  throw new Error('PrivaCage web root element is missing.');
}

mount(App, { target });
