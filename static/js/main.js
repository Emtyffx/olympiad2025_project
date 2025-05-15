$(function () {

  $('.main-slide').slick({  // Простий слайдер
    dots: true, // Крапки під слайдером
    autoplay: true, // Автоматичне пересування слайдера
    autoplaySpeed: 6000, // Швидкість пересування
    prevArrow: '<button type="button" class="slick-prev"> <i class="slider__prev fa fa-angle-left"></i> </button>',
    nextArrow: '<button type="button" class="slick-next"> <i class="slider__next fa fa-angle-right"></i> </button>'
  });



// Відкриття модальних вікон
  $('.menu__registr').click(function (e) { // Реестрація 
        e.preventDefault ();
        $('#exampleModal-1').arcticmodal();
    });

  $('.menu__exit').click(function (e) { // Вхід 
        e.preventDefault ();
        $('#exampleModal-2').arcticmodal();
    });

  $('.but-block').click(function (e) { // Клік на день в календарі
        e.preventDefault ();
        $('#exampleModal-3').arcticmodal();
    });

   $('.podii').click(function (e) { // Клік на день в календарі
        e.preventDefault ();
        $('#exampleModal-4').arcticmodal();
    });

   $('.podii-2').click(function (e) { // Клік на день в календарі
        e.preventDefault ();
        $('#exampleModal-5').arcticmodal();
    });

   $('.task-for-one').click(function (e) { // Особисте завдання
        e.preventDefault ();
        $('#exampleModal-6').arcticmodal();
    });

   $('.task-for-group').click(function (e) { // Групове завдання
        e.preventDefault ();
        $('#exampleModal-7').arcticmodal();
    });

   $('.assessment').click(function (e) { // Оцінювання
        e.preventDefault ();
        $('#exampleModal-8').arcticmodal();
    });

   $('.remove-student').click(function (e) { // Вилучення учня з бази
        e.preventDefault ();
        $('#exampleModal-9').arcticmodal();
    });

   $('.general-event').click(function (e) { // Клік на день в календарі для додавання події
        e.preventDefault ();
        $('#exampleModal-10').arcticmodal();
    });

   $('.desc-date-in').click(function (e) { // Додавання самої події
        e.preventDefault ();
        $('#exampleModal-11').arcticmodal();
    });

   $('.but-block').click(function (e) { // Перегляд подій по кліку в календарі/кабінет учня
        e.preventDefault ();
        $('#exampleModal-12').arcticmodal();
    });

   $('.podii-2').click(function (e) { // Перегляд усіх подій/кабінет учня
        e.preventDefault ();
        $('#exampleModal-13').arcticmodal();
    });

   $('.in-desk-info').click(function (e) { // Перегляд усіх подій/кабінет учня
        e.preventDefault ();
        $('#exampleModal-14').arcticmodal();
    });

});




//Передача инфо о кнопке в модальное окно
$(function() {
    $('.btn-offer-l, .btn-order-l').click(function() {
        var parent = $(this).attr('data-parent');
        var modal = $(this).attr('data-target')
        $(modal).find('input[name=target]').val(parent);
    })
});


//Валидация и отправка формы
$(document).ready(function() {
    $('[data-submit]').on('click', function(e) {
        e.preventDefault();
        $(this).parent('form').submit();
    })
    $.validator.addMethod(
        "regex",
        function(value, element, regexp) {
            var re = new RegExp(regexp);
            return this.optional(element) || re.test(value);
        },
        "Please check your input."
    );

    // Функция валидации и вывода сообщений
    function valEl(el) {
        el.validate({
            rules: {
                login: {
                    required: true,
                //    regex: '^[а-яА-ЯёЁa-zA-Z-1-9]+$'
                },
                name: {
                    required: true,
                    regex: '^[а-яА-ЯёЁіІїЇєЄґҐa-zA-Z]+$'
                },
                surname: {
                    required: true,
                    regex: '^[а-яА-ЯёЁіІїЇєЄґҐa-zA-Z]+$'
                },
                tel: {
                    required: true,
                    regex: '^([\+]+)*[0-9\x20\x28\x29\-]{5,20}$'
                },
                class: {
                    required: true
                },
                radio: {
                    required: true
                },
                message: {
                    required: true
                },
                password: {
                    required: true
                }
            },
            messages: {
                login: {
                    required: 'Поле потрібно заповнити!*',
                    regex: 'Логін не може бути таким!*'
                },
                name: {
                    required: 'Поле потрібно заповнити!*',
                    regex: "Ім`я не може бути таким!*"
                },
                surname: {
                    required: 'Поле потрібно заповнити!*',
                    regex: 'Призвіще не може бути таким!*'
                },
                tel: {
                    required: 'Поле потрібно заповнити!*',
                    regex: 'Телефон може записуватись з + та () !*'
                },
                message: {
                    required: 'Напешіть своє повідомлення!*'
                },
                password: {
                    required: 'Поле потрібно заповнити!*'
                }
            },

            // Начинаем проверку id="" формы
            submitHandler: function(form) {
            	$.arcticmodal('close');
                $('#loader').fadeIn();
                var $form = $(form);
                var $formId = $(form).attr('id');
                switch ($formId) {
                    // Если у формы id="goToNewPage" - делаем:
                    case 'goToNewPage':
                        $.ajax({
                                type: 'POST',
                                url: $form.attr('action'),
                                data: $form.serialize(),
                            })
                            .always(function(response) {
                                //ссылка на страницу "спасибо" - редирект
                                location.href = 'https://wayup.in/lm/landing-page-marathon/success';
                                //отправка целей в Я.Метрику и Google Analytics
                                ga('send', 'event', 'masterklass7', 'register'); // Google Analytics
                                yaCounter27714603.reachGoal('lm17lead');  // Я.Метрикa
                            });
                        break;
                    // Если у формы id="popupResult" - делаем:
                    case 'popupResult-1':
                        $.ajax({
                                type: 'POST',
                                url: $form.attr('action'),
                                data: $form.serialize(),
                            })
                            .always(function(response) {
                                setTimeout(function() {
                                    $('#loader').fadeOut();
                                }, 800);
                                setTimeout(function() {
                                    // Отримуємо введенный логин
                                    var userLogin = $('#login-f1').val();
                                    // створюємо та показуємо повідомлення
                                    $('#overlay').html('<div class="success-message" style="background: white; padding: 20px; border-radius: 5px; text-align: center;">' +
                                    '<h3>Дякуємо за реєстрацію на нашій платформі!</h3>' +
                                    '<p>Ваш логін: <strong>' + userLogin + '</strong></p>' +
                                    '</div>');
                                    $('#overlay').fadeIn();
                                    $form.trigger('reset');
                                    //рядки для відслідковування цілей в Я.Метрике и Google Analytics
                                }, 1100);
                                $('#overlay').on('click', function(e) {
                                    $(this).fadeOut();
                                });
                            });
                        break;
                    case 'popupResult-2':
                        $.ajax({
                                type: 'POST',
                                url: $form.attr('action'),
                                data: $form.serialize(),
                            })
                            .always(function(response) {
                                setTimeout(function() {
                                    $('#loader').fadeOut();
                                }, 800);
                                setTimeout(function() {
                                    $('#overlay').fadeIn();
                                    $form.trigger('reset');
                                    //строки для остлеживания целей в Я.Метрике и Google Analytics
                                }, 1100);
                                $('#overlay').on('click', function(e) {
                                    $(this).fadeOut();
                                });
                            });
                        break;
                    // Если у формы id="StaticResult" - делаем:
                    case 'staticResult':
                        $.ajax({
                                type: 'POST',
                                url: $form.attr('action'),
                                data: $form.serialize(),
                            })
                            .always(function(response) {
                                setTimeout(function() {
                                    $('#loader').fadeOut();
                                }, 800);
                                setTimeout(function() {
                                    $('#overlay').fadeIn();
                                    $form.trigger('reset');
                                    //строки для остлеживания целей в Я.Метрике и Google Analytics
                                }, 1100);
                                $('#overlay').on('click', function(e) {
                                    $(this).fadeOut();
                                });
                            });
                        break;
                }
                return false;
            }
        })
    }

    // Запускаем механизм валидации форм, если у них есть класс .js-form
    $('.js-form').each(function() {
        valEl($(this));
    });
    
});
