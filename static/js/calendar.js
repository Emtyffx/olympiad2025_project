var Cal = function(divId) 
{
	this.divId = divId;
	this.DaysOfWeek = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Нд'];
	this.Months = ['Січень', 'Лютий', 'Березень', 'Квітень', 'Травень', 'Червень', 'Липень', 'Серпень', 'Вересень', 'Жовтень', 'Листопад', 'Грудень'];
	var d = new Date();
	this.currMonth = d.getMonth();
	this.currYear = d.getFullYear();
	this.currDay = d.getDate();
	this.events = [];
};

Cal.prototype.fetchEvents = async function() 
{
	try 
    {
		const response = await fetch('/api/events', 
            {
				method: 'GET',
				headers: 
                {
					'Content-Type': 'application/json'
				}
			});
			this.events = await response.json();
			console.log('Події з API:', this.events);
		} 
        catch (error) 
        {
			console.error('Помилка при отриманні подій:', error);
		}
	};

	Cal.prototype.nextMonth = function() 
    {
		if (this.currMonth == 11) 
        {
			this.currMonth = 0;
			this.currYear = this.currYear + 1;
		} 
        else 
        {
			this.currMonth = this.currMonth + 1;
		}
		this.showcurr();
	};

	Cal.prototype.previousMonth = function() 
    {
	    if (this.currMonth == 0) 
        {
			this.currMonth = 11;
			this.currYear = this.currYear - 1;
		} 
        else 
        {
			this.currMonth = this.currMonth - 1;
		}
		this.showcurr();
	};

	Cal.prototype.showcurr = function() 
    {
		this.showMonth(this.currYear, this.currMonth);
	};

	Cal.prototype.showMonth = function(y, m) 
    {
		var d = new Date();
		var firstDayOfMonth = new Date(y, m, 7).getDay();
		var lastDateOfMonth = new Date(y, m + 1, 0).getDate();
		var lastDayOfLastMonth = m == 0 ? new Date(y - 1, 11, 0).getDate() : new Date(y, m, 0).getDate();

		// Оновлюємо назву місяця та року
		document.getElementById('monthYear').textContent = this.Months[m] + ' ' + y;

		var html = '<table>';
		html += '<tr class="days">';
		for (var i = 0; i < this.DaysOfWeek.length; i++) 
        {
			html += '<td>' + this.DaysOfWeek[i] + '</td>';
		}
		html += '</tr>';

		var i = 1;
		do 
        {
			var dow = new Date(y, m, i).getDay();
			if (dow == 1) 
            {
				html += '<tr>';
			} 
            else if (i == 1) 
            {
				html += '<tr>';
				var k = lastDayOfLastMonth - firstDayOfMonth + 1;
				for (var j = 0; j < firstDayOfMonth; j++) 
                {
					html += '<td class="not-current">' + k + '</td>';
					k++;
				}
			}

			var currentDate = new Date(y, m, i);
			var eventsForDay = this.events.filter(event => 
            {
				var eventDate = new Date(event.date);
				return eventDate.getFullYear() === y &&
					   eventDate.getMonth() === m &&
					   eventDate.getDate() === i;
			});

			var hasEvent = eventsForDay.length > 0;
			var isPastEvent = false;
			if (hasEvent) 
            {
				const now = new Date();
				isPastEvent = eventsForDay.every(event => 
                {
					const eventDate = new Date(event.date);
					return eventDate < now;
				});
			}

			var chk = new Date();
			var chkY = chk.getFullYear();
			var chkM = chk.getMonth();
			if (chkY == this.currYear && chkM == this.currMonth && i == this.currDay) 
            {
				html += `<td class="today${hasEvent ? (isPastEvent ? ' past-event-day' : ' event-day') : ''}"><a href="#" class="but-block but-block-${i}" onclick="calendarInstance.showDayEvents(${y}, ${m}, ${i}); return false;">${i}</a></td>`;
			} 
            else 
            {
				html += `<td class="normal${hasEvent ? (isPastEvent ? ' past-event-day' : ' event-day') : ''}"><a href="#" class="but-block but-block-${i}" onclick="calendarInstance.showDayEvents(${y}, ${m}, ${i}); return false;">${i}</a></td>`;
			}

			if (dow == 0) 
            {
				html += '</tr>';
			} 
            else if (i == lastDateOfMonth) 
            {
				var k = 1;
				for (dow; dow < 7; dow++) 
                {
					html += '<td class="not-current">' + k + '</td>';
					k++;
				}
			}
			i++;
		} 
        while (i <= lastDateOfMonth);

		html += '</table>';
		document.getElementById(this.divId).innerHTML = html;
	};

	Cal.prototype.showDayEvents = function(year, month, day) 
    {
		const selectedDate = new Date(year, month, day);
		const dayOfWeek = this.DaysOfWeek[selectedDate.getDay() === 0 ? 6 : selectedDate.getDay() - 1];
		const dateStr = `${day} ${this.Months[month].toUpperCase()} ${year} - ${dayOfWeek}`;
		document.getElementById('selectedDate').textContent = dateStr;

		const eventsOnDay = this.events.filter(event => 
        {
			const eventDate = new Date(event.date);
			return eventDate.getFullYear() === year &&
		    eventDate.getMonth() === month &&
			eventDate.getDate() === day;
		});

		const eventContainer = document.getElementById('eventDetails');
		eventContainer.innerHTML = '';

		if (eventsOnDay.length > 0) 
        {
			eventsOnDay.forEach(event => 
            {
				const eventDate = new Date(event.date);
				const timeStr = eventDate.toTimeString().slice(0, 5);
				const eventHtml = `
					<div>
						<h2 class="event-title">${event.title || 'Без назви'}</h2>
						<p class="event-desc">Час проведення: ${timeStr}</p>
					</div>
				`;
				eventContainer.innerHTML += eventHtml;
			});
		} 
        else 
        {
			eventContainer.innerHTML = `
				<p>Не заплановано ніяких подій</p>
			`;
		}

		try 
        {
			$.arcticmodal(
        {
				content: '#exampleModal-3'
				});
		} 
        catch (error) 
        {
			console.error('Помилка при відкритті модального вікна (#exampleModal-3):', error);
			alert('Не вдалося відкрити модальне вікно. Перевірте консоль для деталей.');
		}
	};

	Cal.prototype.showAllEvents = function() 
    {
		document.getElementById('currentMonth').textContent = this.Months[this.currMonth] + ' ' + this.currYear;

		const eventList = document.getElementById('eventList');
		eventList.innerHTML = '';

		const daysInMonth = new Date(this.currYear, this.currMonth + 1, 0).getDate();

		for (let day = 1; day <= daysInMonth; day++) 
        {
			const eventsForDay = this.events.filter(event => 
            {
				const eventDate = new Date(event.date);
				return eventDate.getFullYear() === this.currYear && eventDate.getMonth() === this.currMonth && eventDate.getDate() === day;
			});

			const li = document.createElement('li');
			li.classList.add('event-item');
			if (eventsForDay.length > 0) 
            {
				li.classList.add('activ-event-day');
				const now = new Date();
				const isPastEvent = eventsForDay.every(event => 
                {
					const eventDate = new Date(event.date);
					return eventDate < now;
				});
				li.classList.add(isPastEvent ? 'past' : 'future');
				eventsForDay.forEach(event => 
                {
					const eventDate = new Date(event.date);
					const hours = String(eventDate.getHours()).padStart(2, '0');
					const minutes = String(eventDate.getMinutes()).padStart(2, '0');
					const time = `${hours}:${minutes}`;
					const eventLi = document.createElement('div');
					eventLi.classList.add('event-subitem');
					eventLi.innerHTML = `<p>${day} - ${event.title || 'Без назви'} (${time})</p>`;
					li.appendChild(eventLi);
				});
			} 
            else 
            {
				li.classList.add('event-absent');
				li.innerHTML = `<p>${day}</p><p>Не заплановано ніяка подія</p>`;
			}
			eventList.appendChild(li);
		}

		try 
        {
			$.arcticmodal(
            {
				content: '#exampleModal-4'
			});
		} 
        catch (error) 
        {
			console.error('Помилка при відкритті модального вікна (#exampleModal-4):', error);
			alert('Не вдалося відкрити модальне вікно. Перевірте консоль для деталей.');
		}
	};

	// Ініціалізація календаря
	const calendarInstance = new Cal('divCal');

	// Завантажуємо події та відображаємо календар
	calendarInstance.fetchEvents().then(() => 
    {
		calendarInstance.showcurr();
	});

	// Прив’язка подій до кнопок
	document.getElementById('btnPrev').addEventListener('click', () => calendarInstance.previousMonth());
	document.getElementById('btnNext').addEventListener('click', () => calendarInstance.nextMonth());
	document.querySelector('.podii-2').addEventListener('click', (e) =>
    {
		e.preventDefault();
		calendarInstance.showAllEvents();
	});

	// Відкриття модальних вікон для реєстрації та входу
	document.querySelector('.menu__registr').addEventListener('click', (e) => 
    {
		e.preventDefault();
		$.arcticmodal(
        {
			content: '#exampleModal-1'
		});
	});

	document.querySelector('.menu__exit').addEventListener('click', (e) =>
    {
		e.preventDefault();
		$.arcticmodal(
        {
			content: '#exampleModal-2'
		});
	});